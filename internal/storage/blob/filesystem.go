//go:build darwin || linux

// Package blob provides private storage primitives for trusted service composition.
// Callers must authorize every invocation and existence response before using it.
package blob

import (
 "bufio"
 "bytes"
 "compress/gzip"
 "context"
 "crypto/rand"
 "crypto/sha256"
 "encoding/binary"
 "encoding/hex"
 "errors"
 "hash"
 "io"
 "math"
 "os"
 "strings"
 "sync"
 "syscall"

 "canopy.local/canopy/internal/model"
)

var (
 ErrInvalidArgument = errors.New("invalid blob argument")
 ErrNotFound = errors.New("blob not found")
 ErrCorruptData = errors.New("corrupt blob data")
 ErrResourceExhausted = errors.New("blob resource exhausted")
 ErrUnavailable = errors.New("blob storage unavailable")
 ErrOutcomeUnknown = errors.New("blob activation outcome unknown")
 ErrClosed = errors.New("blob store closed")
 ErrBusy = errors.New("blob store busy")
)

type Options struct { MaxPayload uint64; MaxEncodedBytes uint64; MaxConcurrentOps int; RecoveryBatch int }
type PutResult struct { ID model.BlobID; PayloadBytes uint64; Reused bool }
// Filesystem assumes a trusted launcher, trusted ancestors and one root writer.
// It does not defend against hostile same-UID/root or mount administrators.
type Filesystem struct {
 mu sync.Mutex
 root, staging *os.Root
 dir, stage *os.File
 path string
 opts Options
 ops diskOps
 active int
 recoveryErr error
 ready, closing, closed bool
 changed chan struct{}
}
// Copied once by the private constructor; no runtime setter or mutable global.
type diskOps struct { before func(string) error }
func (s *Filesystem) step(point string) error { if s.ops.before != nil { return s.ops.before(point) }
 return nil }
func diskError(err error) error {
 if err == nil { return nil }
  var p *os.PathError; if errors.As(err, &p) { err = p.Err }
 if errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EDQUOT) { return errors.Join(ErrResourceExhausted, err) }
 return errors.Join(ErrUnavailable, err)
}
func secure(info os.FileInfo, mode os.FileMode, dir bool) bool {
 if info == nil { return false }
  st, ok := info.Sys().(*syscall.Stat_t)
 return ok && st.Uid == uint32(os.Geteuid()) && info.Mode() == mode && info.IsDir() == dir
}
func same(a, b os.FileInfo) bool { return a != nil && b != nil && os.SameFile(a, b) }
func openAt(r *os.Root, name string, flags int, mode os.FileMode) (*os.File, error) {
 return r.OpenFile(name, flags|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, mode)
}
func OpenFilesystem(rootPath string, opts Options) (*Filesystem, error) { return openFilesystem(rootPath, opts, diskOps{}) }
func openFilesystem(path string, opts Options, ops diskOps) (_ *Filesystem, err error) {
 if path == "" || opts.MaxPayload > model.MaxBlobPayload || opts.MaxEncodedBytes < 50 || opts.MaxEncodedBytes > math.MaxInt64 || opts.MaxConcurrentOps <= 0 || opts.RecoveryBatch <= 0 { return nil, ErrInvalidArgument }
 s := &Filesystem{path:path, opts:opts, ops:ops, changed:make(chan struct{})}
 defer func(){ if err != nil { if s.stage != nil { s.stage.Close() }
  if s.staging != nil { s.staging.Close() }
  if s.dir != nil { s.dir.Close() }
  if s.root != nil { s.root.Close() } } }()
 s.dir, err = os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0); if err != nil { return nil, diskError(err) }
 info, err := s.dir.Stat(); if err != nil { return nil, diskError(err) }
  if !secure(info, os.ModeDir|0700, true) { return nil, ErrUnavailable }
 s.root, err = os.OpenRoot(path); if err != nil { return nil, diskError(err) }
 err = s.root.Mkdir(".staging",0700); if err != nil && !errors.Is(err,os.ErrExist) { return nil,diskError(err) }
 s.stage, err = openAt(s.root,".staging",os.O_RDONLY|syscall.O_DIRECTORY,0); if err != nil { return nil,diskError(err) }
 s.staging, err = s.root.OpenRoot(".staging"); if err != nil { return nil,diskError(err) }
 if err = s.checkDirs(); err != nil { return nil,err }
 if err = s.dir.Sync(); err != nil { return nil,diskError(err) }
 return s,nil
}
func (s *Filesystem) checkDirs() error {
 a,e1 := s.dir.Stat(); b,e2 := os.Lstat(s.path); c,e3 := s.root.Lstat(".")
 d,e4 := s.stage.Stat(); e,e5 := s.root.Lstat(".staging"); f,e6 := s.staging.Lstat(".")
 if err := errors.Join(e1,e2,e3,e4,e5,e6); err != nil { return diskError(err) }
 if !secure(a,os.ModeDir|0700,true) || !secure(b,os.ModeDir|0700,true) || !same(a,b) || !same(a,c) || !secure(d,os.ModeDir|0700,true) || !secure(e,os.ModeDir|0700,true) || !same(d,e) || !same(d,f) || a.Sys().(*syscall.Stat_t).Dev!=d.Sys().(*syscall.Stat_t).Dev { return ErrUnavailable }
  return nil
}
func (s *Filesystem) acquire(ctx context.Context) error {
 if s == nil || ctx == nil { return ErrInvalidArgument }
 for {
  if err := ctx.Err(); err != nil { return err }
   s.mu.Lock()
  if s.changed == nil { s.mu.Unlock(); return ErrInvalidArgument }
  if s.closing { s.mu.Unlock(); return ErrClosed }
   if !s.ready { s.mu.Unlock(); return ErrBusy }
  if s.active < s.opts.MaxConcurrentOps { s.active++; s.mu.Unlock(); return nil }
  ch := s.changed; s.mu.Unlock(); select { case <-ctx.Done(): return ctx.Err(); case <-ch: }
 }
}
func (s *Filesystem) release() { s.mu.Lock(); s.active--; close(s.changed); s.changed=make(chan struct{}); s.mu.Unlock() }
func (s *Filesystem) Close() error {
 if s == nil { return ErrInvalidArgument }
  s.mu.Lock(); defer s.mu.Unlock()
 if s.changed == nil { return ErrInvalidArgument }
  if s.closed { return nil }
  s.closing=true
 close(s.changed); s.changed=make(chan struct{}); if s.active != 0 { return ErrBusy }
 s.closed=true; return diskError(errors.Join(s.stage.Close(),s.staging.Close(),s.dir.Close(),s.root.Close()))
}
func tempName(name string) bool { if len(name)!=36 || !strings.HasSuffix(name,".tmp") { return false }
 b,err:=hex.DecodeString(name[:32]); return err==nil && hex.EncodeToString(b)==name[:32] }
func (s *Filesystem) RecoverTemps(ctx context.Context) (done bool, err error) {
 if s == nil || ctx == nil { return false,ErrInvalidArgument }
  s.mu.Lock(); defer s.mu.Unlock()
 if s.changed == nil { return false,ErrInvalidArgument }
  if s.recoveryErr!=nil{return false,s.recoveryErr}
 defer func(){if err!=nil{s.recoveryErr=err}}(); if s.closing { return false,ErrClosed }
  if s.ready || s.active!=0 { return false,ErrBusy }
 if err:=ctx.Err();err!=nil{return false,err}
  if err:=s.checkDirs();err!=nil{return false,err}
 entries,err:=s.stage.ReadDir(s.opts.RecoveryBatch); if err!=nil && err!=io.EOF{return false,diskError(err)}
 for _,entry:=range entries {
  if err:=ctx.Err();err!=nil{return false,err}
   info,e:=s.staging.Lstat(entry.Name())
  if e!=nil{return false,diskError(e)}
  if !tempName(entry.Name()) || (!secure(info,0600,false) && !secure(info,0400,false)) { return false,ErrCorruptData }
  if e=s.staging.Remove(entry.Name());e!=nil{return false,diskError(e)}
 }
 if e:=s.stage.Sync();e!=nil{return false,diskError(e)}
  if err==io.EOF { s.ready=true }
  return s.ready,nil
}
func blobName(id model.BlobID) string { b,_:=id.TypedID().MarshalBinary()
return "blob-v1-"+hex.EncodeToString(b) }
func envelope(codec byte,payload,body uint64) []byte {
 b:=make([]byte,28);copy(b,"CBLOB\x00\x00\x00");binary.BigEndian.PutUint16(b[8:10],1);b[10]=codec;binary.BigEndian.PutUint64(b[12:20],payload);binary.BigEndian.PutUint64(b[20:28],body)
 return b
}
// localReader always consumes the GZIP footer, then checks the single-member
// boundary, exact expanded count and canonical digest before successful EOF.
type localReader struct {
 ctx context.Context
 file *os.File
 limited *io.LimitedReader
 buffered *bufio.Reader
 zip *gzip.Reader
 src io.Reader
 digest hash.Hash
 expected [32]byte
 total, canonical uint64
 terminal error
 release func()
 closed bool
}
func (s *Filesystem) reader(ctx context.Context,f *os.File,id model.BlobID) (*localReader,uint64,error) {
 if _,err:=f.Seek(0,0);err!=nil{return nil,0,diskError(err)}
 info,err:=f.Stat()
 if err!=nil{return nil,0,diskError(err)}
 if !secure(info,0400,false) { return nil,0,ErrCorruptData }
  var h [28]byte
 if _,err=io.ReadFull(f,h[:]);err!=nil{return nil,0,errors.Join(ErrCorruptData,err)}
 payload,body:=binary.BigEndian.Uint64(h[12:20]),binary.BigEndian.Uint64(h[20:28])
 if string(h[:8])!="CBLOB\x00\x00\x00" || binary.BigEndian.Uint16(h[8:10])!=1 || h[11]!=0 || h[10]>1 {return nil,0,ErrCorruptData}
 if payload>s.opts.MaxPayload || body>s.opts.MaxEncodedBytes-28 {return nil,0,ErrResourceExhausted}
 if body>math.MaxInt64-28 || info.Size()!=int64(body+28) || body==0 {return nil,0,ErrCorruptData}
 if (payload+22-1)/64+1>body {return nil,0,ErrResourceExhausted}
 r:=&localReader{ctx:ctx,file:f,limited:&io.LimitedReader{R:f,N:int64(body)},digest:sha256.New(),expected:id.TypedID().Digest(),canonical:payload+22}
 r.buffered=bufio.NewReaderSize(r.limited,32<<10);r.src=r.buffered
 if h[10]==1 {r.zip,err=gzip.NewReader(r.buffered)
 if err!=nil{return nil,0,errors.Join(ErrCorruptData,err)}
 r.zip.Multistream(false);r.src=r.zip}
 return r,payload,nil
}
func (r *localReader) Read(p []byte) (int,error) {
 if r.closed{return 0,ErrClosed}
  if r.terminal!=nil{return 0,r.terminal}
 if err:=r.ctx.Err();err!=nil{r.terminal=err
 return 0,err}
 if len(p)==0{return 0,nil}
 want:=min(uint64(len(p)),uint64(32<<10),r.canonical-r.total+1);n,err:=r.src.Read(p[:int(want)])
 if n<0 || n>int(want){n=0;err=ErrCorruptData}
 r.total+=uint64(n);r.digest.Write(p[:n])
 if r.total>r.canonical {err=ErrCorruptData}
 if err==io.EOF {
  var digest [32]byte;copy(digest[:],r.digest.Sum(nil));_,extra:=r.buffered.ReadByte()
  if r.total!=r.canonical || digest!=r.expected || extra!=io.EOF || r.limited.N!=0 {err=ErrCorruptData}
  if err==io.EOF {var b [1]byte; k,e:=r.file.Read(b[:])
  if k!=0 || e!=io.EOF {err=errors.Join(ErrCorruptData,e)}}
 } else if err!=nil {err=errors.Join(ErrCorruptData,err)}
 if cancel:=r.ctx.Err();cancel!=nil{err=cancel}
 if err!=nil{r.terminal=err}
 return n,err
}
func (r *localReader) Close() error {
 if r.closed{return nil}
 r.closed=true;var err error
 if r.zip!=nil{err=r.zip.Close()}
 err=errors.Join(err,diskError(r.file.Close()))
 if r.terminal!=nil && r.terminal!=io.EOF{err=errors.Join(err,r.terminal)}
 if r.release!=nil{r.release()}
 return err
}
func (s *Filesystem) verified(ctx context.Context,f *os.File,id model.BlobID) (*localReader,uint64,error) {
 r,p,err:=s.reader(ctx,f,id)
 if err!=nil{return nil,0,err}
 n,err:=model.DecodeBlob(ctx,r,id,io.Discard,s.opts.MaxPayload)
 if r.zip!=nil{err=errors.Join(err,r.zip.Close())}
 if err!=nil{return nil,0,err}
 if n!=p{return nil,0,ErrCorruptData}
 return s.reader(ctx,f,id)
}
func (s *Filesystem) openFinal(name string) (*os.File,error) {
 before,e:=s.root.Lstat(name)
 if e!=nil {if errors.Is(e,os.ErrNotExist){return nil,ErrNotFound};return nil,diskError(e)}
 if !secure(before,0400,false){return nil,ErrCorruptData}
 f,err:=openAt(s.root,name,os.O_RDONLY,0)
 if err!=nil {
  if errors.Is(err,os.ErrNotExist){return nil,ErrNotFound}
   if errors.Is(err,syscall.ELOOP){return nil,ErrCorruptData}
  return nil,diskError(err)
 }
  info,err:=f.Stat()
 if err!=nil || !secure(info,0400,false) || !same(before,info){f.Close()
 return nil,errors.Join(ErrCorruptData,err)}
 return f,nil
}
func (s *Filesystem) OpenCanonical(ctx context.Context,id model.BlobID) (io.ReadCloser,error) {
 if ctx==nil || id.Validate()!=nil{return nil,ErrInvalidArgument}
 if err:=s.acquire(ctx);err!=nil{return nil,err}
 ok:=false;defer func(){if !ok{s.release()}}()
 if err:=s.checkDirs();err!=nil{return nil,err}
 f,err:=s.openFinal(blobName(id))
 if err!=nil{return nil,err}
 r,_,err:=s.verified(ctx,f,id)
 if err!=nil{f.Close()
 return nil,err}
 r.release=s.release;ok=true
 return r,nil
}
type cappedWriter struct { s *Filesystem; f *os.File; n uint64 }
func (w *cappedWriter) Write(p []byte) (int,error) {
 if uint64(len(p))>w.s.opts.MaxEncodedBytes-w.n{return 0,ErrResourceExhausted}
 if err:=w.s.step("write");err!=nil{return 0,diskError(err)}
 n,err:=w.f.Write(p);w.n+=uint64(n)
 if err!=nil{return n,diskError(err)}
 if n!=len(p){return n,io.ErrShortWrite}
 return n,nil
}
func compareReaders(a,b io.Reader) error {
 var x,y [32<<10]byte
 for {n,e:=io.ReadFull(a,x[:]);m,f:=io.ReadFull(b,y[:])
 if n!=m || !bytes.Equal(x[:n],y[:m]){return ErrCorruptData}
  if e!=nil || f!=nil {if e==f && (e==io.EOF || e==io.ErrUnexpectedEOF){return nil}
  return errors.Join(ErrCorruptData,e,f)}
 }
}
func (s *Filesystem) Put(ctx context.Context,id model.BlobID,declaredPayload uint64,canonicalFrame io.Reader) (result PutResult,err error) {
 if ctx==nil || canonicalFrame==nil || id.Validate()!=nil || s==nil{return result,ErrInvalidArgument}
 if declaredPayload>model.MaxBlobPayload || declaredPayload>s.opts.MaxPayload{return result,ErrInvalidArgument}
 if err=s.acquire(ctx);err!=nil{return result,err}
 defer s.release()
 if err=s.checkDirs();err!=nil{return result,err}
 var f *os.File;var name string
 for i:=0;i<16;i++ {var b [16]byte
 if _,err=rand.Read(b[:]);err!=nil{return result,diskError(err)}
 name=hex.EncodeToString(b[:])+".tmp";f,err=openAt(s.staging,name,os.O_RDWR|os.O_CREATE|os.O_EXCL,0600)
 if !errors.Is(err,os.ErrExist){break}}
 if err!=nil{return result,diskError(err)}
 activated,committed,present:=false,false,true
 defer func(){
  if f!=nil {err=errors.Join(err,diskError(f.Close()))}
  if present {e:=s.staging.Remove(name)
  if e==nil{e=s.stage.Sync()}
  err=errors.Join(err,diskError(e))}
  if err!=nil {result=PutResult{}
  if activated && !committed{err=errors.Join(ErrOutcomeUnknown,err)}}
 }()
 info,e:=f.Stat()
 if e!=nil || !secure(info,0600,false){return result,errors.Join(ErrUnavailable,e)}
 w:=&cappedWriter{s:s,f:f}
 if _,err=w.Write(make([]byte,28));err!=nil{return result,err}
 z,_:=gzip.NewWriterLevel(w,gzip.HuffmanOnly)
 n,e:=model.DecodeBlob(ctx,io.TeeReader(canonicalFrame,z),id,io.Discard,declaredPayload);ze:=z.Close()
 if e!=nil{return result,errors.Join(ErrInvalidArgument,e,ze)}
 if ze!=nil{return result,ze}
 if n!=declaredPayload{return result,ErrInvalidArgument}
 if _,err=f.WriteAt(envelope(1,n,w.n-28),0);err!=nil{return result,diskError(err)}
 if err=f.Chmod(0400);err!=nil{return result,diskError(err)}
 r,_,e:=s.verified(ctx,f,id)
 if e!=nil{return result,e}
 if r.zip!=nil{r.zip.Close()}
 if err=s.step("fileSync");err==nil{err=f.Sync()}
 if err!=nil{return result,diskError(err)}
 info,err=f.Stat()
 if err!=nil{return result,diskError(err)}
 e=f.Close();f=nil;err=errors.Join(e,s.step("close"))
 if err!=nil{return result,diskError(err)}
 if err=s.checkDirs();err!=nil{return result,err}
 current,e:=s.staging.Lstat(name)
 if e!=nil || !same(info,current) || !secure(current,0400,false){return result,errors.Join(ErrUnavailable,e)}
 if err=s.step("beforeLink");err!=nil{return result,diskError(err)}
 if err=ctx.Err();err!=nil{return result,err}
 if err=s.checkDirs();err!=nil{return result,err}
 current,e=s.staging.Lstat(name)
 if e!=nil || !same(info,current) || !secure(current,0400,false){return result,errors.Join(ErrUnavailable,e)}
 final:=blobName(id);err=s.step("link")
 if err==nil{err=s.root.Link(".staging/"+name,final)}
 reused:=errors.Is(err,os.ErrExist)
 if err!=nil && !reused{return result,diskError(err)}
 activated=!reused
 if err=s.step("afterLink");err!=nil{return result,diskError(err)}
 if err=ctx.Err();err!=nil{return result,err}
 existing,e:=s.openFinal(final)
 if e!=nil{return result,e}
 defer func(){err=errors.Join(err,diskError(existing.Close()))}()
 if reused {
  old,_,e:=s.verified(ctx,existing,id)
  if e!=nil{return result,e}
  defer func(){if old.zip!=nil{old.zip.Close()}}()
  candidate,e:=openAt(s.staging,name,os.O_RDONLY,0)
  if e!=nil{return result,diskError(e)}
  defer func(){err=errors.Join(err,diskError(candidate.Close()))}()
  fresh,_,e:=s.reader(ctx,candidate,id)
  if e!=nil{return result,e}
  defer func(){if fresh.zip!=nil{fresh.zip.Close()}}()
  if err=compareReaders(old,fresh);err!=nil{return result,err}
 }
 if err=s.step("finalSync");err==nil{err=existing.Sync()}
 if err!=nil{return result,diskError(err)}
 if err=s.step("remove");err==nil{err=s.staging.Remove(name)}
 if err!=nil{return result,diskError(err)}
 present=false
 if err=s.step("directorySync");err==nil{err=s.dir.Sync()}
 if err!=nil{return result,diskError(err)}
 if err=s.step("stagingSync");err==nil{err=s.stage.Sync()}
 if err!=nil{return result,diskError(err)}
 committed=true
 return PutResult{ID:id,PayloadBytes:n,Reused:reused},nil
}
