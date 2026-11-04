//go:build darwin || linux

// Command fuzz runs deterministic, bounded mutation campaigns against existing
// primitives. It is not coverage-guided Go fuzzing: the authorized issue scope
// contains no _test.go driver. Build before running so every case executes the
// same binary: go build -o /tmp/scion-fuzz ./tests/fuzz
// Example: /tmp/scion-fuzz -target=all -iterations=100 -seed=60 -corpus=/tmp/seeds
// Replay: /tmp/scion-fuzz -target=paths -replay=/tmp/seeds/<hash>.original
//
// Each case has a subprocess deadline; panics, nonzero exits, timeouts and OOM
// termination are failures, never skipped coverage. The 64 MiB Go memory target
// is SOFT, not an OS RSS cap. Run under an OS memory limit for hard qualification.
// Expected parser/admission rejection of hostile inputs is not harness resource
// exhaustion. Failure files retain exact original bytes, best bounded reduction,
// target, seed and diagnostics. Reduction is deletion-only and capped at 64
// probes; it does not claim a globally minimal crash. Never delete failing seeds.
// Files are fsynced, but directory entries are not: this is not power-loss-safe
// corpus storage. Case deadlines cover worker processes, not coordinator file
// I/O. Use a healthy local filesystem; a stalled mount can block preservation.
// Nonblocking/no-follow opens reject special files but cannot bound disk stalls.
//
// This prepares TST-02; no campaign, #53 acceptance, real RPC transport, storage
// durability, or cloud/scale qualification is implied. Changesets here exercises
// the canonical model codec, not the COM-01 publication dependency ports.
package main

import (
 "bytes"
 "compress/gzip"
 "context"
 "crypto/sha256"
 "encoding/binary"
 "encoding/hex"
 "encoding/json"
 "errors"
 "flag"
 "fmt"
 "io"
 "math/rand"
 "os"
 "os/exec"
 "path/filepath"
 "runtime/debug"
 "regexp"
 "strings"
 "sync"
 "syscall"
 "time"

 "canopy.local/canopy/internal/authz"
 "canopy.local/canopy/internal/model"
)

const maxInput = 65535
var targets = []string{"paths", "blob", "changesets", "admission"}

type settings struct {
 target, corpus, replay string
 iterations int
 seed int64
 timeout time.Duration
 worker bool
}
func main() {
 var s settings
 flag.StringVar(&s.target,"target","all","paths, blob, changesets, admission, or all")
 flag.StringVar(&s.corpus,"corpus","","directory for preserved failures (required for campaigns)")
 flag.StringVar(&s.replay,"replay","","replay exact saved input without mutation")
 flag.IntVar(&s.iterations,"iterations",100,"mutations per target, 1..1000")
 flag.Int64Var(&s.seed,"seed",60,"deterministic mutation seed")
 flag.DurationVar(&s.timeout,"timeout",2*time.Second,"per-case deadline, 100ms..10s")
 flag.BoolVar(&s.worker,"worker",false,"internal one-case subprocess")
 flag.Parse()
 if err:=run(s);err!=nil { fmt.Fprintln(os.Stderr,err);os.Exit(1) }
}
func run(s settings) error {
 if s.worker {
  debug.SetMemoryLimit(64<<20)
  data,err:=io.ReadAll(io.LimitReader(os.Stdin,maxInput+1))
  if err!=nil{return err};if len(data)>maxInput{return errors.New("input budget exceeded")}
  return check(s.target,data)
 }
 if s.timeout<100*time.Millisecond || s.timeout>10*time.Second || s.iterations<1 || s.iterations>1000{return errors.New("invalid campaign bounds")}
 selected:=targets
 if s.target!="all" { selected=[]string{s.target};if !known(s.target){return errors.New("unknown target")} }
 if s.replay!="" {
  if s.target=="all" {return errors.New("replay requires exact target")}
  f,err:=os.OpenFile(s.replay,os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK,0);if err!=nil{return err}
  info,err:=f.Stat();if err!=nil{f.Close();return err};if !ownedMode(info,0600){f.Close();return errors.New("replay requires an owned regular 0600 seed")}
  data,err:=io.ReadAll(io.LimitReader(f,maxInput+1));closeErr:=f.Close()
  if err!=nil{return err};if closeErr!=nil{return closeErr};if len(data)>maxInput{return errors.New("replay exceeds input budget")}
  if failed,_,detail:=probe(s,s.target,data);failed{return fmt.Errorf("replay failed: %s",detail)}
  fmt.Println("replay passed");return nil
 }
 if time.Duration(len(selected)*(s.iterations+10)+64)*s.timeout>40*time.Minute {return errors.New("requested worst-case probe time exceeds 40-minute campaign budget")}
 if s.corpus=="" {return errors.New("campaign requires -corpus for failure preservation")}
 corpus,err:=openCorpus(s.corpus);if err!=nil{return err};defer corpus.Close()
 rng:=rand.New(rand.NewSource(s.seed))
 for _,target:=range selected {
  seeds,err:=seedInputs(target);if err!=nil{return err}
  caseCount:=len(seeds)+s.iterations
  for index:=0;index<caseCount;index++ {
   var data []byte
   if index<len(seeds){data=seeds[index]}else{data=mutate(rng,seeds[rng.Intn(len(seeds))])}
   if failed,class,detail:=probe(s,target,data);failed {
    // Save original BEFORE reduction; an interrupted reduction cannot lose it.
    original,err:=save(corpus,s.corpus,target,data,"original");if err!=nil{return fmt.Errorf("failure %s; preserve error: %w",detail,err)}
    reduced:=append([]byte(nil),data...)
    for probes,span:=0,len(reduced)/2;span>0 && probes<64; {
     changed:=false
     for start:=0;start+span<=len(reduced) && probes<64;start+=span {
      candidate:=append(append([]byte(nil),reduced[:start]...),reduced[start+span:]...)
      probes++
      bad,kind,_:=probe(s,target,candidate)
      if bad && kind==class {reduced=candidate;changed=true;break}
     }
     if !changed {span/=2}
    }
    minimized,err:=save(corpus,s.corpus,target,reduced,"minimized");if err!=nil{return err}
    record:=map[string]any{"target":target,"seed":s.seed,"case":index,"timeout":s.timeout.String(),"original":original,"minimized":minimized,"failure":detail,"failure_class":class,"time_utc":time.Now().UTC().Format(time.RFC3339),"reduction":"deletion-only, at most 64 probes; same stable failure classification required"}
    encoded,err:=json.MarshalIndent(record,"","  ");if err!=nil{return err}
    if _,err=save(corpus,s.corpus,target,encoded,"json");err!=nil{return err}
    return fmt.Errorf("%s failed; original %s, reduced %s: %s",target,original,minimized,detail)
   }
  }
  fmt.Printf("%s passed %d seed/mutation cases (seed=%d)\n",target,caseCount,s.seed)
 }
 return nil
}
func known(target string) bool {for _,name:=range targets{if name==target{return true}};return false}
// The corpus must be a private directory owned by this UID. Trusted parent
// directories and no hostile same-UID/root process are prerequisites. Hold an
// os.Root rather than re-resolving paths; final components never follow links.
func openCorpus(path string)(*os.Root,error){
 if err:=os.MkdirAll(path,0700);err!=nil{return nil,err}
 dir,err:=os.OpenFile(path,os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY,0)
 if err!=nil{return nil,err};defer dir.Close()
 info,err:=dir.Stat();if err!=nil{return nil,err}
 if !ownedMode(info,os.ModeDir|0700){return nil,errors.New("corpus must be an owned private 0700 directory")}
 root,err:=os.OpenRoot(path);if err!=nil{return nil,err}
 actual,err:=root.Lstat(".")
 if err!=nil || !os.SameFile(info,actual){root.Close();return nil,errors.New("corpus identity changed while opening")}
 return root,nil
}
func ownedMode(info os.FileInfo,mode os.FileMode)bool{
 if info==nil || info.Mode()!=mode{return false}
 stat,ok:=info.Sys().(*syscall.Stat_t)
 return ok && stat.Uid==uint32(os.Geteuid())
}
// Store by target and content hash using exclusive creation. An existing name
// must open no-follow/nonblocking and be an owned regular 0600 file. Thus a
// pre-existing symlink/FIFO/device is an error, never followed or read. Existing
// regular artifacts are bounded-read and compared, never overwritten.
func save(root *os.Root,dir,target string,data []byte,suffix string)(string,error){
 sum:=sha256.Sum256(data);name:=target+"-"+hex.EncodeToString(sum[:])+"."+suffix;path:=filepath.Join(dir,name)
 f,err:=root.OpenFile(name,os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_NONBLOCK,0600)
 if errors.Is(err,os.ErrExist){
  existing,e:=root.OpenFile(name,os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK,0);if e!=nil{return "",e}
  info,e:=existing.Stat();if e!=nil{existing.Close();return "",e}
  if !ownedMode(info,0600){existing.Close();return "",errors.New("existing corpus artifact is not an owned regular 0600 file")}
  old,e:=io.ReadAll(io.LimitReader(existing,int64(len(data))+1));closeErr:=existing.Close()
  if e!=nil{return "",e};if closeErr!=nil{return "",closeErr};if !bytes.Equal(old,data){return "",errors.New("existing corpus content mismatch")};return path,nil
 }
 if err!=nil{return "",err}
 info,err:=f.Stat();if err!=nil{f.Close();return "",err}
 if !ownedMode(info,0600){f.Close();return "",errors.New("new corpus artifact is not an owned regular 0600 file")}
 _,err=f.Write(data);if err==nil{err=f.Sync()};closeErr:=f.Close();if err!=nil{return "",err};if closeErr!=nil{return "",closeErr};return path,nil
}
type boundedLog struct {mu sync.Mutex;data []byte}
func (b *boundedLog) Write(p []byte)(int,error){b.mu.Lock();defer b.mu.Unlock();n:=len(p);remaining:=4096-len(b.data);if len(p)>remaining{p=p[:remaining]};b.data=append(b.data,p...);return n,nil}
var volatileFailure = regexp.MustCompile(`0x[0-9a-fA-F]+|[0-9]+`)
func probe(s settings,target string,data []byte)(bool,string,string){
 executable,err:=os.Executable();if err!=nil{return true,"harness/executable",err.Error()}
 ctx,cancel:=context.WithTimeout(context.Background(),s.timeout);defer cancel()
 cmd:=exec.CommandContext(ctx,executable,"-worker","-target="+target)
 cmd.Stdin=bytes.NewReader(data);output:=&boundedLog{};cmd.Stdout=output;cmd.Stderr=output
 err=cmd.Run()
 if ctx.Err()!=nil{return true,"resource/deadline","case deadline exceeded"}
 if err!=nil{
  detail:=fmt.Sprintf("%v: %s",err,output.data)
  var exit *exec.ExitError
  if !errors.As(err,&exit){return true,"harness/launch",detail}
  first:=strings.SplitN(string(output.data),"\n",2)[0]
  // Panic stacks contain addresses, goroutine IDs and varying index values.
  // Keep the error category/first line, not unstable stack diagnostics.
  termination:=fmt.Sprintf("exit/%d",exit.ExitCode())
  if status,ok:=exit.Sys().(syscall.WaitStatus);ok && status.Signaled(){termination="signal/"+status.Signal().String()}
  class:=termination+"/"+volatileFailure.ReplaceAllString(first,"#")
  return true,class,detail
 }
 return false,"",""
}
func mutate(r *rand.Rand,seed []byte)[]byte{
 data:=append([]byte(nil),seed...)
 for i,n:=0,1+r.Intn(8);i<n;i++{
  switch r.Intn(4){
  case 0:if len(data)>0{data[r.Intn(len(data))]^=byte(1<<r.Intn(8))}
  case 1:if len(data)<maxInput{at:=r.Intn(len(data)+1);data=append(data,0);copy(data[at+1:],data[at:]);data[at]=byte(r.Intn(256))}
  case 2:if len(data)>0{at:=r.Intn(len(data));data=append(data[:at],data[at+1:]...)}
  case 3:if len(data)>0{data=data[:r.Intn(len(data)+1)]}
  }
 }
 return data
}
func seedInputs(target string)([][]byte,error){
 base:=[][]byte{nil,[]byte("a"),[]byte("../a"),{0,255,47},[]byte("a//b"),[]byte("a/b"),bytes.Repeat([]byte("x"),maxInput)}
 var frame bytes.Buffer
 if err:=model.EncodeBlob(context.Background(),&frame,3,bytes.NewReader([]byte("abc")));err!=nil{return nil,err}
 if target=="blob" {return append(base,frame.Bytes()),nil}
 if target=="changesets" {
  value,err:=model.NewChangeset(model.ChangesetInput{RepoID:[16]byte{1}});if err!=nil{return nil,err}
  frame.Reset();if err=model.EncodeChangeset(context.Background(),&frame,value);err!=nil{return nil,err};return append(base,frame.Bytes()),nil
 }
 if target=="admission" {
  raw:=append([]byte{0,0,3},frame.Bytes()...)
  var zipped bytes.Buffer;z:=gzip.NewWriter(&zipped)
  if _,err:=z.Write(frame.Bytes());err!=nil{return nil,err};if err:=z.Close();err!=nil{return nil,err}
  compressed:=append([]byte{1,0,3},zipped.Bytes()...)
  var empty bytes.Buffer;emptyZip:=gzip.NewWriter(&empty);if err:=emptyZip.Close();err!=nil{return nil,err}
  twoMembers:=append(append([]byte(nil),compressed...),empty.Bytes()...)
  return append(base,raw,compressed,twoMembers),nil
 }
 return base,nil
}
func check(target string,data []byte)error{
 switch target{case "paths":return checkPath(data);case "blob":return checkBlob(data);case "changesets":return checkChangeset(data);case "admission":return checkAdmission(data)}
 return errors.New("unknown target")
}
func checkPath(data []byte)error{
 valid:=len(data)>0 && len(data)<=int(model.MaxPathBytes) && !bytes.ContainsRune(data,0)
 parts:=bytes.Split(data,[]byte{'/'})
 if len(parts)>int(model.MaxPathComponents){valid=false}
 for _,part:=range parts{if len(part)==0 || bytes.Equal(part,[]byte(".")) || bytes.Equal(part,[]byte("..")){valid=false}}
 path,err:=model.NewPath(data)
 if (err==nil)!=valid{return errors.New("path grammar differs from oracle")}
 if err!=nil{return nil}
 original:=append([]byte(nil),data...)
 if len(data)>0{data[0]^=255}
 if !bytes.Equal(path.Bytes(),original){return errors.New("path aliases caller input")}
 copyOut:=path.Bytes();copyOut[0]^=255
 if !bytes.Equal(path.Bytes(),original){return errors.New("path exposes mutable internal bytes")}
 return nil
}
func checkBlob(data []byte)error{
 digest:=sha256.Sum256(data);typed,err:=model.NewTypedID(model.BlobKind,digest);if err!=nil{return err};id,err:=model.NewBlobID(typed);if err!=nil{return err}
 var payload bytes.Buffer
 wrongDigest:=digest;wrongDigest[0]^=1
 wrongTyped,e:=model.NewTypedID(model.BlobKind,wrongDigest);if e!=nil{return e};wrongID,e:=model.NewBlobID(wrongTyped);if e!=nil{return e}
 if _,e=model.DecodeBlob(context.Background(),bytes.NewReader(data),wrongID,io.Discard,maxInput);e==nil{return errors.New("blob accepted independently mismatched digest")}
 n,err:=model.DecodeBlob(context.Background(),bytes.NewReader(data),id,&payload,maxInput)
 if err==nil{
  var encoded bytes.Buffer
  if err=model.EncodeBlob(context.Background(),&encoded,n,bytes.NewReader(payload.Bytes()));err!=nil{return err}
  if !bytes.Equal(encoded.Bytes(),data){return errors.New("accepted blob does not reencode exactly")}
 }else if n!=0{return errors.New("rejected blob returned accepted length")}
 // Every mutation also exercises a valid encode/decode path, not only rejection.
 var frame bytes.Buffer
 if err=model.EncodeBlob(context.Background(),&frame,uint64(len(data)),bytes.NewReader(data));err!=nil{return err}
 id,err=model.HashBlob(context.Background(),uint64(len(data)),bytes.NewReader(data));if err!=nil{return err}
 payload.Reset();n,err=model.DecodeBlob(context.Background(),bytes.NewReader(frame.Bytes()),id,&payload,maxInput)
 if err!=nil{return err};if n!=uint64(len(data)) || !bytes.Equal(payload.Bytes(),data){return errors.New("blob roundtrip mismatch")};return nil
}
func checkChangeset(data []byte)error{
 digest:=sha256.Sum256(data);typed,err:=model.NewTypedID(model.ChangesetKind,digest);if err!=nil{return err};id,err:=model.NewChangesetID(typed);if err!=nil{return err}
 wrongDigest:=digest;wrongDigest[0]^=1
 wrongTyped,e:=model.NewTypedID(model.ChangesetKind,wrongDigest);if e!=nil{return e};wrongID,e:=model.NewChangesetID(wrongTyped);if e!=nil{return e}
 if _,e=model.DecodeChangeset(context.Background(),bytes.NewReader(data),wrongID,maxInput);e==nil{return errors.New("changeset accepted independently mismatched digest")}
 value,err:=model.DecodeChangeset(context.Background(),bytes.NewReader(data),id,maxInput)
 if err!=nil{return nil}
 var encoded bytes.Buffer
 if err=model.EncodeChangeset(context.Background(),&encoded,value);err!=nil{return err}
 if !bytes.Equal(encoded.Bytes(),data){return errors.New("accepted changeset does not reencode exactly")};return nil
}
func checkAdmission(data []byte)error{
 limits:=authz.DefaultAdmissionLimits();limits.Bounds[authz.AdmissionWholeFrameBytes]=maxInput+22;limits.Bounds[authz.AdmissionWholeEncodedBytes]=maxInput
 admission,err:=authz.NewAdmission(limits);if err!=nil{return err}
 // Use independent metadata fields to exercise overflow-sized declarations,
 // unsupported request kinds, nesting and forbidden message compression.
 var meta [11]byte;copy(meta[:],data)
 kind:=authz.AdmissionRequestKind(meta[0]);declared:=binary.BigEndian.Uint64(meta[3:11]);depth:=uint64(meta[1]);compressed:=meta[2]&1!=0
 cap:=uint64(2097152)
 if kind==authz.AdmissionUploadRequest{cap=8388608};if kind==authz.AdmissionResponse{cap=16777216}
 allowed:=kind<=authz.AdmissionResponse && !compressed && depth<=16 && declared<=cap
 if (admission.CheckRequest(kind,declared,depth,compressed)==nil)!=allowed{return errors.New("request admission differs from metadata oracle")}
 if len(data)<3{return nil} // finite grammar: incomplete outer fixture is invalid
 spec:=authz.AdmissionObject{Kind:model.BlobKind,PayloadBytes:uint64(binary.BigEndian.Uint16(data[1:3])),InputBytes:uint64(len(data)-3),Compression:authz.AdmissionCompression(data[0]),Whole:true}
 permit,err:=admission.Acquire(context.Background(),authz.PrincipalID{Issuer:"fuzz",Subject:"local",Class:authz.ServiceAccount});if err!=nil{return err};defer permit.Release()
 var output bytes.Buffer
 n,err:=permit.CopyObject(context.Background(),&output,bytes.NewReader(data[3:]),spec)
 if output.Len()>maxInput+22{return errors.New("admission exceeded fixture output bound")}
 if err!=nil{return nil}
 if n!=spec.PayloadBytes+22 || uint64(output.Len())!=n{return errors.New("admission accepted wrong output length")}
 switch spec.Compression {
 case authz.AdmissionRaw:if !bytes.Equal(output.Bytes(),data[3:]){return errors.New("RAW changed bytes")}
 case authz.AdmissionGZIP:
  source:=bytes.NewReader(data[3:]);z,e:=gzip.NewReader(source);if e!=nil{return e};z.Multistream(false)
  decoded,e:=io.ReadAll(io.LimitReader(z,maxInput+23));closeErr:=z.Close();if e!=nil{return e};if closeErr!=nil{return closeErr}
  if source.Len()!=0{return errors.New("GZIP accepted trailing bytes or additional member")}
  if !bytes.Equal(decoded,output.Bytes()){return errors.New("GZIP changed bytes")}
  if (n+63)/64>uint64(len(data)-3){return errors.New("GZIP accepted excessive expansion ratio")}
 default:return errors.New("unknown codec accepted")
 }
 // Request metadata is checked independently of object decoding.
 if err=admission.CheckRequest(authz.AdmissionReadRequest,uint64(len(data)),1,false);err!=nil{return fmt.Errorf("bounded request unexpectedly rejected: %w",err)}
 return nil
}
