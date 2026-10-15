//go:build darwin || linux

package blob

import (
 "bytes"
 "compress/gzip"
 "context"
 "encoding/binary"
 "errors"
 "io"
 "os"
 "path/filepath"
 "sync"
 "syscall"
 "testing"
 "time"

 "canopy.local/canopy/internal/model"
)

func privateDir(t *testing.T) string { t.Helper();p:=t.TempDir();if e:=os.Chmod(p,0700);e!=nil{t.Fatal(e)};return p }

// Deterministic fixture seed: OBJ02-STORE-v1. No random payloads/crash helpers.
func fixture(t *testing.T,p []byte) (model.BlobID,[]byte) {
 t.Helper();id,e:=model.HashBlob(context.Background(),uint64(len(p)),bytes.NewReader(p))
 if e!=nil{t.Fatal(e)}
 var b bytes.Buffer
 if e=model.EncodeBlob(context.Background(),&b,uint64(len(p)),bytes.NewReader(p));e!=nil{t.Fatal(e)}
 return id,b.Bytes()
}
func options() Options {return Options{MaxPayload:1<<20,MaxEncodedBytes:2<<20,MaxConcurrentOps:2,RecoveryBatch:2}}
func ready(t *testing.T,root string,opts Options,ops diskOps) *Filesystem {
 t.Helper();s,e:=openFilesystem(root,opts,ops)
 if e!=nil{t.Fatal(e)}
 for {done,e:=s.RecoverTemps(context.Background())
 if e!=nil{t.Fatal(e)}
 if done{break}}
 t.Cleanup(func(){if e:=s.Close();e!=nil{t.Error(e)}})
 return s
}
func requireError(t *testing.T,err,want error) {t.Helper()
if !errors.Is(err,want){t.Fatalf("got %v, want %v",err,want)}}
func put(t *testing.T,s *Filesystem,id model.BlobID,frame []byte,n uint64) PutResult {
 t.Helper();r,e:=s.Put(context.Background(),id,n,bytes.NewReader(frame))
 if e!=nil{t.Fatal(e)}
 if r.ID!=id || r.PayloadBytes!=n{t.Fatal("wrong result")}
 return r
}
func seed(t *testing.T,root string,id model.BlobID,frame []byte,codec byte,level int) []byte {
 t.Helper();body:=frame
 if codec==1{var b bytes.Buffer;z,e:=gzip.NewWriterLevel(&b,level)
 if e!=nil{t.Fatal(e)}
 if _,e=z.Write(frame);e!=nil{t.Fatal(e)}
 if e=z.Close();e!=nil{t.Fatal(e)}
 body=b.Bytes()}
 data:=append(envelope(codec,uint64(len(frame)-22),uint64(len(body))),body...)
 if e:=os.WriteFile(filepath.Join(root,blobName(id)),data,0400);e!=nil{t.Fatal(e)}
 return data
}
func noTemps(t *testing.T,root string){t.Helper();xs,e:=os.ReadDir(filepath.Join(root,".staging"))
if e!=nil || len(xs)!=0{t.Fatalf("temps %v %v",xs,e)}}
func TestStoreRoundTrip(t *testing.T) {
 for _,tc:=range []struct{name string;p []byte}{{"empty",nil},{"binary",[]byte{0,255,128}},{"small",[]byte("OBJ02-STORE-v1")},{"multibuffer",bytes.Repeat([]byte{0,1,255},32768)}}{t.Run(tc.name,func(t *testing.T){
  root:=privateDir(t);s:=ready(t,root,options(),diskOps{});id,frame:=fixture(t,tc.p);r:=put(t,s,id,frame,uint64(len(tc.p)))
  if r.Reused{t.Fatal("unexpected reuse")}
  noTemps(t,root)
  for path,mode:=range map[string]os.FileMode{root:0700,filepath.Join(root,".staging"):0700,filepath.Join(root,blobName(id)):0400}{info,e:=os.Lstat(path)
  if e!=nil || info.Mode().Perm()!=mode || info.Sys().(*syscall.Stat_t).Uid!=uint32(os.Geteuid()){t.Fatal("unsafe mode/owner",e)}}
  data,e:=os.ReadFile(filepath.Join(root,blobName(id)))
  if e!=nil{t.Fatal(e)}
  if len(data)<28 || data[10]!=1 || binary.BigEndian.Uint64(data[20:28])!=uint64(len(data)-28){t.Fatal("envelope")}
  z,e:=gzip.NewReader(bytes.NewReader(data[28:]))
  if e!=nil{t.Fatal(e)}
  raw,e:=io.ReadAll(z)
  if e!=nil || !bytes.Equal(raw,frame){t.Fatal("gzip verification",e)}
  z.Close()
  if e=s.Close();e!=nil{t.Fatal(e)}
  s=ready(t,root,options(),diskOps{});rd,e:=s.OpenCanonical(context.Background(),id)
  if e!=nil{t.Fatal(e)}
  var payload bytes.Buffer;n,e:=model.DecodeBlob(context.Background(),rd,id,&payload,options().MaxPayload)
  if e!=nil || n!=uint64(len(tc.p)) || !bytes.Equal(payload.Bytes(),tc.p){t.Fatal("canonical read",e)}
  if e=rd.Close();e!=nil{t.Fatal(e)}
 })}
}
func TestStoreImmutableDedup(t *testing.T) {
 for _,tc:=range []struct{name string;codec byte;level int}{{"raw",0,0},{"alternateGzip",1,gzip.BestCompression},{"replay",2,0}}{t.Run(tc.name,func(t *testing.T){
  root:=privateDir(t);s:=ready(t,root,options(),diskOps{});id,frame:=fixture(t,[]byte("immutable canonical content"))
  if tc.codec==2{put(t,s,id,frame,27)}else{seed(t,root,id,frame,tc.codec,tc.level)}
  path:=filepath.Join(root,blobName(id));before,_:=os.Stat(path);data,_:=os.ReadFile(path)
  if !put(t,s,id,frame,27).Reused{t.Fatal("not reused")}
  after,_:=os.Stat(path);now,_:=os.ReadFile(path)
  if !os.SameFile(before,after) || !bytes.Equal(data,now){t.Fatal("replaced existing")}
  noTemps(t,root)
 })}
}
func TestStoreConcurrentDedup(t *testing.T) {
 root:=privateDir(t);s:=ready(t,root,options(),diskOps{});id,frame:=fixture(t,bytes.Repeat([]byte("x"),70000));var wg sync.WaitGroup;results:=make(chan PutResult,2);errs:=make(chan error,2)
 for i:=0;i<2;i++{wg.Add(1);go func(){defer wg.Done();r,e:=s.Put(context.Background(),id,70000,bytes.NewReader(frame));results<-r;errs<-e}()}
 wg.Wait();close(results);close(errs)
 for e:=range errs{if e!=nil{t.Fatal(e)}}
 reused:=0;for r:=range results{if r.ID!=id{t.Fatal("ID")}
 if r.Reused{reused++}}
 if reused!=1{t.Fatal("conditional link",reused)}
 noTemps(t,root)
}
type rejectReader struct{ calls int }
func (r *rejectReader) Read([]byte)(int,error){r.calls++
return 0,io.ErrUnexpectedEOF}
func TestStoreRejectInput(t *testing.T) {
 root:=privateDir(t);s:=ready(t,root,options(),diskOps{});id,frame:=fixture(t,[]byte("payload"));other,_:=fixture(t,[]byte("another"))
 cases:=[]struct{name string;id model.BlobID;n uint64;b []byte}{{"zeroID",model.BlobID{},7,frame},{"declaredMismatch",id,6,frame},{"configuredLimit",id,(1<<20)+1,frame},{"overflow",id,^uint64(0),frame},{"headerTruncated",id,7,frame[:10]},{"payloadTruncated",id,7,frame[:len(frame)-1]},{"extra",id,7,append(append([]byte{},frame...),0)},{"wrongDigest",other,7,frame},{"wrongVersion",id,7,append([]byte{},frame...)},{"wrongKind",id,7,append([]byte{},frame...)}}
 cases[8].b[12]=2;cases[9].b[13]=byte(model.ChangesetKind)
 for _,tc:=range cases{t.Run(tc.name,func(t *testing.T){r,e:=s.Put(context.Background(),tc.id,tc.n,bytes.NewReader(tc.b));requireError(t,e,ErrInvalidArgument)
 if r!=(PutResult{}){t.Fatal("partial success")}
 if _,e=os.Stat(filepath.Join(root,blobName(id)));!errors.Is(e,os.ErrNotExist){t.Fatal("activated")}
 noTemps(t,root)})}
 t.Run("modelMaximumBounded",func(t *testing.T){opts:=options();opts.MaxPayload=model.MaxBlobPayload;st:=ready(t,privateDir(t),opts,diskOps{});r:=&rejectReader{}
 _,e:=st.Put(context.Background(),id,model.MaxBlobPayload,r);requireError(t,e,ErrInvalidArgument)
 if r.calls!=1{t.Fatal("unbounded source reads")}})
 t.Run("encodedCap",func(t *testing.T){opts:=options();opts.MaxEncodedBytes=50;st:=ready(t,privateDir(t),opts,diskOps{});_,e:=st.Put(context.Background(),id,7,bytes.NewReader(frame));requireError(t,e,ErrResourceExhausted)})
}
func TestStoreRejectEnvelope(t *testing.T) {
 id,frame:=fixture(t,[]byte("footer fixture"))
 cases:=[]string{"crc","isize","footerTruncated","headerTruncated","members","bodyTrailing","fileTrailing","version","codec","reserved","rawDigest","payloadCap","encodedCap","ratio"}
 for _,name:=range cases{t.Run(name,func(t *testing.T){
  root:=privateDir(t);s:=ready(t,root,options(),diskOps{});data:=seed(t,root,id,frame,1,gzip.HuffmanOnly)
  switch name{case "crc":data[len(data)-8]^=1;case "isize":data[len(data)-1]^=1;case "footerTruncated":data=data[:len(data)-3];binary.BigEndian.PutUint64(data[20:28],uint64(len(data)-28));case "headerTruncated":data=data[:30];binary.BigEndian.PutUint64(data[20:28],2)
  case "members":data=append(data,data[28:]...);binary.BigEndian.PutUint64(data[20:28],uint64(len(data)-28));case "bodyTrailing":data=append(data,1);binary.BigEndian.PutUint64(data[20:28],uint64(len(data)-28));case "fileTrailing":data=append(data,1);case "version":data[9]=2;case "codec":data[10]=2;case "reserved":data[11]=1
  case "rawDigest":data=append(envelope(0,14,uint64(len(frame))),frame...);data[len(data)-1]^=1
  case "payloadCap":binary.BigEndian.PutUint64(data[12:20],(1<<20)+1);case "encodedCap":binary.BigEndian.PutUint64(data[20:28],2<<20);case "ratio":binary.BigEndian.PutUint64(data[12:20],100000)
  }
  path:=filepath.Join(root,blobName(id))
  if e:=os.Chmod(path,0600);e!=nil{t.Fatal(e)}
  if e:=os.WriteFile(path,data,0400);e!=nil{t.Fatal(e)}
  os.Chmod(path,0400)
  rd,e:=s.OpenCanonical(context.Background(),id);want:=ErrCorruptData
  if name=="payloadCap" || name=="encodedCap" || name=="ratio"{want=ErrResourceExhausted}
  requireError(t,e,want)
  if rd!=nil{t.Fatal("reader escaped")}
  before,_:=os.Stat(path);_,e=s.Put(context.Background(),id,14,bytes.NewReader(frame));requireError(t,e,want);after,_:=os.Stat(path);now,_:=os.ReadFile(path)
  if !os.SameFile(before,after) || !bytes.Equal(data,now){t.Fatal("corrupt destination overwritten")}
  noTemps(t,root)
 })}
}
func TestStoreUnsafePaths(t *testing.T) {
 for _,name:=range []string{"rootMode","rootSymlink","stagingMode","stagingSymlink","finalMode","finalSymlink","finalDirectory"}{t.Run(name,func(t *testing.T){
  root:=privateDir(t);outside:=privateDir(t);sentinel:=filepath.Join(outside,"sentinel");os.WriteFile(sentinel,[]byte("outside"),0600);id,frame:=fixture(t,[]byte("safe"))
  switch name{case "rootMode":os.Chmod(root,0750);defer os.Chmod(root,0700);case "rootSymlink":root=filepath.Join(privateDir(t),"link");os.Symlink(outside,root);case "stagingMode":os.Mkdir(filepath.Join(root,".staging"),0755);case "stagingSymlink":os.Symlink(outside,filepath.Join(root,".staging"))}
  s,e:=OpenFilesystem(root,options())
  if name=="rootMode" || name=="rootSymlink" || name=="stagingMode" || name=="stagingSymlink"{if e==nil{s.Close();t.Fatal("unsafe constructor")}}else{
   if e!=nil{t.Fatal(e)}
   defer s.Close()
   if _,e=s.RecoverTemps(context.Background());e!=nil{t.Fatal(e)}
   path:=filepath.Join(root,blobName(id))
   switch name{case "finalMode":os.WriteFile(path,[]byte("occupied"),0600);case "finalSymlink":os.Symlink(sentinel,path);case "finalDirectory":os.Mkdir(path,0700)}
   _,e=s.Put(context.Background(),id,4,bytes.NewReader(frame));requireError(t,e,ErrCorruptData);rd,e:=s.OpenCanonical(context.Background(),id);requireError(t,e,ErrCorruptData)
   if rd!=nil{t.Fatal("unsafe reader")}
  }
  b,e:=os.ReadFile(sentinel)
  if e!=nil || string(b)!="outside"{t.Fatal("outside changed",e)}
 })}
}
// Owner mismatch branch is deterministic without privileged chown. Actual
// foreign-UID fixtures are unavailable to this unprivileged local test process.
type foreignInfo struct {os.FileInfo; stat syscall.Stat_t}
func (f foreignInfo) Sys() any {return &f.stat}
func TestStoreOwnerCheck(t *testing.T){info,e:=os.Stat(privateDir(t))
if e!=nil{t.Fatal(e)}
st:=*info.Sys().(*syscall.Stat_t);st.Uid++
if secure(foreignInfo{info,st},os.ModeDir|0700,true){t.Fatal("foreign owner accepted")}}
func TestStoreRecoveryAndAdmission(t *testing.T) {
 root:=privateDir(t);os.Mkdir(filepath.Join(root,".staging"),0700);for _,n:=range []string{"00000000000000000000000000000001.tmp","00000000000000000000000000000002.tmp","00000000000000000000000000000003.tmp"}{os.WriteFile(filepath.Join(root,".staging",n),[]byte("orphan"),0600)}
 opts:=options();opts.MaxConcurrentOps=1;s,e:=OpenFilesystem(root,opts)
 if e!=nil{t.Fatal(e)}
 defer s.Close();id,frame:=fixture(t,nil);_,e=s.Put(context.Background(),id,0,bytes.NewReader(frame));requireError(t,e,ErrBusy)
 done,e:=s.RecoverTemps(context.Background())
 if e!=nil || done{t.Fatal("unbounded recovery",done,e)}
 for !done {done,e=s.RecoverTemps(context.Background())
 if e!=nil{t.Fatal("recovery",e)}}
 put(t,s,id,frame,0)
 rd,e:=s.OpenCanonical(context.Background(),id)
 if e!=nil{t.Fatal(e)}
 ctx,cancel:=context.WithTimeout(context.Background(),20*time.Millisecond);defer cancel();_,e=s.OpenCanonical(ctx,id);requireError(t,e,context.DeadlineExceeded)
 requireError(t,s.Close(),ErrBusy)
 if e=rd.Close();e!=nil{t.Fatal(e)}
 requireError(t,func()error{_,e:=s.OpenCanonical(context.Background(),id)
 return e}(),ErrClosed)
 if e=s.Close();e!=nil{t.Fatal(e)}
 noTemps(t,root)
}
type cancelReader struct{ r io.Reader; cancel context.CancelFunc; reads int }
func (r *cancelReader) Read(p []byte)(int,error){n,e:=r.r.Read(p);r.reads++
if r.reads==2{r.cancel()}
return n,e}
func TestStoreCancellationAndSync(t *testing.T) {
 for _,point:=range []string{"canceled","duringCopy","beforeLink","fileSync","directorySync","afterLink"}{t.Run(point,func(t *testing.T){
  root:=privateDir(t);ctx,cancel:=context.WithCancel(context.Background());defer cancel();cause:=syscall.EIO
  s:=ready(t,root,options(),diskOps{before:func(p string)error{if p==point{if p=="beforeLink" || p=="afterLink"{cancel()
  return nil}
  return cause}
  return nil}})
  id,frame:=fixture(t,bytes.Repeat([]byte("abc"),24000));var src io.Reader=bytes.NewReader(frame)
  if point=="canceled"{cancel()}
  if point=="duringCopy"{src=&cancelReader{r:src,cancel:cancel}}
  r,e:=s.Put(ctx,id,72000,src)
  if r!=(PutResult{}){t.Fatal("false success")}
  if point=="fileSync" || point=="directorySync"{requireError(t,e,cause)}else{requireError(t,e,context.Canceled)}
  _,statErr:=os.Stat(filepath.Join(root,blobName(id)))
  if point=="directorySync" || point=="afterLink"{requireError(t,e,ErrOutcomeUnknown)
  if statErr!=nil{t.Fatal("rolled back activation")}}else if !errors.Is(statErr,os.ErrNotExist){t.Fatal("early activation")}
  noTemps(t,root)
 })}
}
func TestStoreInvalidLifetime(t *testing.T){var s *Filesystem;requireError(t,s.Close(),ErrInvalidArgument);var z Filesystem;requireError(t,z.Close(),ErrInvalidArgument);_,e:=OpenFilesystem(privateDir(t),Options{});requireError(t,e,ErrInvalidArgument);r:=ready(t,privateDir(t),options(),diskOps{});id,_:=fixture(t,nil);_,e=r.OpenCanonical(context.Background(),id);requireError(t,e,ErrNotFound)}

func TestStoreRecoveryRejectsSymlink(t *testing.T){
 root:=privateDir(t);outside:=privateDir(t);os.Mkdir(filepath.Join(root,".staging"),0700);name:="00000000000000000000000000000001.tmp";os.Symlink(outside,filepath.Join(root,".staging",name));s,e:=OpenFilesystem(root,options())
 if e!=nil{t.Fatal(e)}
 defer s.Close()
 for i:=0;i<2;i++{_,e=s.RecoverTemps(context.Background());requireError(t,e,ErrCorruptData)}
 info,e:=os.Lstat(filepath.Join(root,".staging",name))
 if e!=nil || info.Mode()&os.ModeSymlink==0{t.Fatal("recovery removed symlink")}
}
func TestStoreReaderCancellation(t *testing.T){
 root:=privateDir(t);s:=ready(t,root,options(),diskOps{});id,frame:=fixture(t,[]byte("reader"));put(t,s,id,frame,6);ctx,cancel:=context.WithCancel(context.Background());r,e:=s.OpenCanonical(ctx,id)
 if e!=nil{t.Fatal(e)}
 cancel();_,e=r.Read(make([]byte,32));requireError(t,e,context.Canceled);requireError(t,r.Close(),context.Canceled)
}
type badSource struct{late bool;frame []byte}
func (r *badSource) Read(p []byte)(int,error){if r.late{n:=copy(p,r.frame)
return n,syscall.EIO}
return 0,nil}
func TestStoreSourceErrors(t *testing.T){
 for _,late:=range []bool{false,true}{name:="noProgress"
 if late{name="lateError"}
 t.Run(name,func(t *testing.T){root:=privateDir(t);s:=ready(t,root,options(),diskOps{});id,frame:=fixture(t,[]byte("bad"));_,e:=s.Put(context.Background(),id,3,&badSource{late:late,frame:frame});want:=error(io.ErrNoProgress)
 if late{want=syscall.EIO}
 requireError(t,e,want);noTemps(t,root)
 if _,e=os.Stat(filepath.Join(root,blobName(id)));!errors.Is(e,os.ErrNotExist){t.Fatal("activated")}})}
}
func TestStoreTempModeAndStagingSubstitution(t *testing.T){
 root:=privateDir(t);outside:=privateDir(t);sentinel:=filepath.Join(outside,"sentinel");os.WriteFile(sentinel,[]byte("outside"),0600);s:=ready(t,root,options(),diskOps{before:func(point string)error{
 if point=="write"{xs,e:=os.ReadDir(filepath.Join(root,".staging"))
 if e!=nil || len(xs)!=1{t.Fatal("temp enumeration",e)}
 info,e:=os.Lstat(filepath.Join(root,".staging",xs[0].Name()))
 if e!=nil || !secure(info,0600,false){t.Fatal("temp ownership/mode",e)}}
 if point=="beforeLink"{if e:=os.Rename(filepath.Join(root,".staging"),filepath.Join(root,".old"));e!=nil{t.Fatal(e)}
 if e:=os.Symlink(outside,filepath.Join(root,".staging"));e!=nil{t.Fatal(e)}}
 return nil}})
 id,frame:=fixture(t,[]byte("staging"));r,e:=s.Put(context.Background(),id,7,bytes.NewReader(frame));requireError(t,e,ErrUnavailable)
 if r!=(PutResult{}){t.Fatal("substitution success")}
 b,e:=os.ReadFile(sentinel)
 if e!=nil || string(b)!="outside"{t.Fatal("outside changed",e)}
 xs,e:=os.ReadDir(filepath.Join(root,".old"))
 if e!=nil || len(xs)!=0{t.Fatal("temp cleanup",e)}
}
