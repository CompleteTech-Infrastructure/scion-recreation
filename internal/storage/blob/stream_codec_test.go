//go:build darwin || linux

package blob

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"testing"

	"canopy.local/canopy/internal/authz"
	"canopy.local/canopy/internal/model"
)

// Deterministic fixture seed: OBJ04-stream-v1. These tests are local primitive
// checks, not storage durability, production memory, or service qualification.
func streamPermit(t *testing.T, limits authz.AdmissionLimits) *authz.AdmissionPermit {
	t.Helper()
	a, err := authz.NewAdmission(limits)
	if err != nil { t.Fatal(err) }
	p, err := a.Acquire(context.Background(), authz.PrincipalID{Issuer:"test", Subject:"stream", Class:authz.ServiceAccount})
	if err != nil { t.Fatal(err) }
	t.Cleanup(p.Release)
	return p
}
func streamFrame(t *testing.T, payload []byte) (model.BlobID, []byte) {
	t.Helper()
	id, err := model.HashBlob(context.Background(), uint64(len(payload)), bytes.NewReader(payload))
	if err != nil { t.Fatal(err) }
	var frame bytes.Buffer
	if err := model.EncodeBlob(context.Background(), &frame, uint64(len(payload)), bytes.NewReader(payload)); err != nil { t.Fatal(err) }
	return id, frame.Bytes()
}
func streamZip(t *testing.T, frame []byte, level int) []byte {
	t.Helper()
	var out bytes.Buffer
	z, err := gzip.NewWriterLevel(&out, level)
	if err != nil { t.Fatal(err) }
	if _,err = z.Write(frame); err != nil { t.Fatal(err) }
	if err = z.Close(); err != nil { t.Fatal(err) }
	return out.Bytes()
}
func streamSpec(payload, encoded int, codec authz.AdmissionCompression) authz.AdmissionObject {
	return authz.AdmissionObject{Kind:model.BlobKind, PayloadBytes:uint64(payload), InputBytes:uint64(encoded), Compression:codec, Whole:true}
}
type streamCountReader struct { src io.Reader; calls, largest int }
func (r *streamCountReader) Read(p []byte) (int,error) { r.calls++; if len(p)>r.largest { r.largest=len(p) }; return r.src.Read(p) }
type streamCountWriter struct { bytes, largest int }
func (w *streamCountWriter) Write(p []byte) (int,error) { w.bytes+=len(p); if len(p)>w.largest { w.largest=len(p) }; return len(p),nil }

func TestBlobEnvelopeRoundTrip(t *testing.T) {
	for _,payload := range [][]byte{nil, {0,255,1}, bytes.Repeat([]byte("OBJ04-stream-v1"),10000)} {
		id,frame:=streamFrame(t,payload)
		for _,codec:=range []authz.AdmissionCompression{authz.AdmissionRaw,authz.AdmissionGZIP} {
			encoded:=frame
			if codec==authz.AdmissionGZIP { encoded=streamZip(t,frame,gzip.HuffmanOnly) }
			in:=&streamCountReader{src:bytes.NewReader(encoded)}
			var got bytes.Buffer
			n,err:=DecodeBlobEnvelope(context.Background(),streamPermit(t,authz.DefaultAdmissionLimits()),&got,in,id,streamSpec(len(payload),len(encoded),codec))
			if err!=nil || n!=uint64(len(payload)) || !bytes.Equal(got.Bytes(),frame) { t.Fatalf("round trip: %d %v",n,err) }
			if in.largest>32768 { t.Fatal("unbounded input read",in.largest) }
		}
	}
}

func TestBlobEnvelopeRejectsMalformed(t *testing.T) {
	payload:=bytes.Repeat([]byte("validation-fixture"),200)
	id,frame:=streamFrame(t,payload)
	for _,name:=range []string{"digest","magic","version","kind","length","truncated","trailing","gzipCRC","gzipTruncated","gzipMembers","gzipTrailing","unknown","oversizedExpansion"} {
		t.Run(name,func(t *testing.T){
			encoded:=append([]byte(nil),frame...)
			spec:=streamSpec(len(payload),len(encoded),authz.AdmissionRaw)
			switch name {
			case "digest": encoded[len(encoded)-1]^=1
			case "magic": encoded[0]^=1
			case "version": encoded[12]=2
			case "kind": encoded[13]=byte(model.ChangesetKind)
			case "length": binary.BigEndian.PutUint64(encoded[14:22],uint64(len(payload)-1))
			case "truncated": encoded=encoded[:len(encoded)-1]
			case "trailing": encoded=append(encoded,0)
			case "unknown": spec.Compression=99
			default:
				encoded=streamZip(t,frame,gzip.HuffmanOnly)
				spec.Compression=authz.AdmissionGZIP
				switch name {
				case "gzipCRC": encoded[len(encoded)-8]^=1
				case "gzipTruncated": encoded=encoded[:len(encoded)-3]
				case "gzipMembers": encoded=append(encoded,encoded...)
				case "gzipTrailing": encoded=append(encoded,1)
				case "oversizedExpansion": spec.PayloadBytes=16
				}
				spec.InputBytes=uint64(len(encoded))
			}
			var staging bytes.Buffer
			n,err:=DecodeBlobEnvelope(context.Background(),streamPermit(t,authz.DefaultAdmissionLimits()),&staging,bytes.NewReader(encoded),id,spec)
			if err==nil || n!=0 { t.Fatalf("accepted malformed %s: %d %v",name,n,err) }
			if name=="unknown" && !errors.Is(err,authz.ErrAdmissionInvalid) { t.Fatal("wrong unknown-codec error",err) }
			if name=="oversizedExpansion" && !errors.Is(err,authz.ErrAdmissionLimit) { t.Fatal("wrong expansion-limit error",err) }
			// staging may contain bytes; they are never accepted on an error.
		})
	}
}

func TestBlobEnvelopeAdmissionBeforeInput(t *testing.T) {
	id,frame:=streamFrame(t,bytes.Repeat([]byte{0},1<<20))
	bomb:=streamZip(t,frame,gzip.BestCompression)
	for _,name:=range []string{"bomb","frameCap","encodedCap","unknown","stagingCap","released"} {
		t.Run(name,func(t *testing.T){
			limits:=authz.DefaultAdmissionLimits()
			encoded:=frame
			spec:=streamSpec(len(frame)-22,len(frame),authz.AdmissionRaw)
			switch name {
			case "bomb": encoded=bomb; spec.InputBytes=uint64(len(bomb)); spec.Compression=authz.AdmissionGZIP
			case "frameCap": limits.Bounds[authz.AdmissionWholeFrameBytes]=32
			case "encodedCap": limits.Bounds[authz.AdmissionWholeEncodedBytes]=32
			case "unknown": spec.Compression=99
			case "stagingCap": limits.Bounds[authz.AdmissionStagingBytes]=32
			}
			p:=streamPermit(t,limits)
			if name=="released" { p.Release() }
			in:=&streamCountReader{src:bytes.NewReader(encoded)}
			n,err:=DecodeBlobEnvelope(context.Background(),p,io.Discard,in,id,spec)
			if err==nil || n!=0 || in.calls!=0 { t.Fatalf("admission consumed input: %d %v calls=%d",n,err,in.calls) }
			want:=authz.ErrAdmissionLimit
			if name=="unknown" { want=authz.ErrAdmissionInvalid }
			if name=="released" { want=authz.ErrAdmissionReleased }
			if !errors.Is(err,want) { t.Fatalf("wrong admission error: got %v want %v",err,want) }
		})
	}
}

type streamFailWriter struct{ err error }
func (w streamFailWriter) Write([]byte)(int,error){ return 0,w.err }
func TestBlobEnvelopeCancellationAndWriterFailure(t *testing.T) {
	id,frame:=streamFrame(t,[]byte("failure"))
	ctx,cancel:=context.WithCancel(context.Background()); cancel()
	n,err:=DecodeBlobEnvelope(ctx,streamPermit(t,authz.DefaultAdmissionLimits()),io.Discard,bytes.NewReader(frame),id,streamSpec(7,len(frame),authz.AdmissionRaw))
	if n!=0 || !errors.Is(err,context.Canceled) { t.Fatal(n,err) }
	cause:=errors.New("staging failed")
	n,err=DecodeBlobEnvelope(context.Background(),streamPermit(t,authz.DefaultAdmissionLimits()),streamFailWriter{cause},bytes.NewReader(frame),id,streamSpec(7,len(frame),authz.AdmissionRaw))
	if n!=0 || !errors.Is(err,cause) { t.Fatal(n,err) }
}

func TestBlobEnvelopeBoundedTransferBuffers(t *testing.T) {
	// This checks transfer sizes, not a measured process-memory bound. Source
	// fixture allocation is test-only; production state holds no frame buffer.
	id,frame:=streamFrame(t,bytes.Repeat([]byte("bounded"),1<<18))
	in:=&streamCountReader{src:bytes.NewReader(frame)}
	out:=&streamCountWriter{}
	n,err:=DecodeBlobEnvelope(context.Background(),streamPermit(t,authz.DefaultAdmissionLimits()),out,in,id,streamSpec(len(frame)-22,len(frame),authz.AdmissionRaw))
	if err!=nil || n!=uint64(len(frame)-22) || out.bytes!=len(frame) { t.Fatal(n,err) }
	if in.largest>32768 || out.largest>32768 { t.Fatal("unbounded transfer",in.largest,out.largest) }
}


// Chunk sizes are deterministic and force the canonical header to span writes.
// Every reader still obeys the caller's requested buffer length.
type streamFragmentReader struct {
 src io.Reader
 sizes []int
 calls int
 cancel context.CancelFunc
}
func (r *streamFragmentReader) Read(p []byte) (int,error) {
 size:=r.sizes[r.calls%len(r.sizes)]
 r.calls++
 if len(p)>size { p=p[:size] }
 n,err:=r.src.Read(p)
 if r.cancel!=nil && r.calls==2 { r.cancel() }
 return n,err
}
func TestBlobEnvelopeFragmentedHeader(t *testing.T) {
 payload:=[]byte("fragmented header and payload")
 id,frame:=streamFrame(t,payload)
 for _,sizes:=range [][]int{{1},{3,1,7,2,4}} {
  t.Run(fmt.Sprint(sizes),func(t *testing.T){
   for _,corrupt:=range []bool{false,true} {
    input:=append([]byte(nil),frame...)
    if corrupt { input[12]=2 }
    in:=&streamFragmentReader{src:bytes.NewReader(input),sizes:sizes}
    var staging bytes.Buffer
    n,err:=DecodeBlobEnvelope(context.Background(),streamPermit(t,authz.DefaultAdmissionLimits()),&staging,in,id,streamSpec(len(payload),len(input),authz.AdmissionRaw))
    if corrupt {
     if n!=0 || !errors.Is(err,ErrCorruptData) { t.Fatalf("fragmented invalid header: %d %v",n,err) }
    } else if err!=nil || n!=uint64(len(payload)) || !bytes.Equal(staging.Bytes(),frame) {
     t.Fatalf("fragmented valid frame: %d %v",n,err)
    }
    if in.calls<4 { t.Fatal("header was not fragmented",in.calls) }
   }
  })
 }
}

type streamBoundaryWriter struct {
 mode string
 cause error
 staging bytes.Buffer
}
func (w *streamBoundaryWriter) Write(p []byte) (int,error) {
 switch w.mode {
 case "negative": return -1,nil
 case "oversized": return len(p)+1,nil
 case "short": return w.staging.Write(p[:len(p)/2])
 case "partialError": n,_:=w.staging.Write(p[:len(p)/2]); return n,w.cause
 case "fullError": n,_:=w.staging.Write(p); return n,w.cause
 default: return 0,errors.New("invalid writer fixture")
 }
}
func TestBlobEnvelopeWriterBoundaries(t *testing.T) {
 id,frame:=streamFrame(t,[]byte("writer boundary payload"))
 cause:=errors.New("partial staging failure")
 for _,mode:=range []string{"negative","oversized","short","partialError","fullError"} {
  t.Run(mode,func(t *testing.T){
   out:=&streamBoundaryWriter{mode:mode,cause:cause}
   n,err:=DecodeBlobEnvelope(context.Background(),streamPermit(t,authz.DefaultAdmissionLimits()),out,bytes.NewReader(frame),id,streamSpec(len(frame)-22,len(frame),authz.AdmissionRaw))
   want:=error(authz.ErrAdmissionInvalid)
   if mode=="short" { want=io.ErrShortWrite }
   if mode=="partialError" || mode=="fullError" { want=cause }
   if n!=0 || !errors.Is(err,want) { t.Fatalf("writer boundary %s: %d %v want %v",mode,n,err,want) }
   if (mode=="short" || mode=="partialError" || mode=="fullError") && out.staging.Len()==0 { t.Fatal("fixture did not write staging bytes") }
  })
 }
}
func TestBlobEnvelopeMidstreamCancellation(t *testing.T) {
 id,frame:=streamFrame(t,[]byte("midstream cancellation payload"))
 ctx,cancel:=context.WithCancel(context.Background())
 defer cancel()
 in:=&streamFragmentReader{src:bytes.NewReader(frame),sizes:[]int{7},cancel:cancel}
 var staging bytes.Buffer
 n,err:=DecodeBlobEnvelope(ctx,streamPermit(t,authz.DefaultAdmissionLimits()),&staging,in,id,streamSpec(len(frame)-22,len(frame),authz.AdmissionRaw))
 if n!=0 || !errors.Is(err,context.Canceled) { t.Fatal(n,err) }
 if in.calls!=2 || staging.Len()!=7 { t.Fatalf("wrong cancellation boundary: reads=%d staged=%d",in.calls,staging.Len()) }
}

func TestBlobEnvelopeCompressionDoesNotChangeIdentity(t *testing.T) {
 payload:=make([]byte,512)
 for i:=range payload { payload[i]=byte(i) }
 id,frame:=streamFrame(t,payload)
 first:=streamZip(t,frame,gzip.HuffmanOnly)
 second:=streamZip(t,frame,gzip.BestCompression)
 if bytes.Equal(first,second) { t.Fatal("fixture must use distinct gzip encodings") }
 for _,encoded:=range [][]byte{first,second} {
  var staging bytes.Buffer
  n,err:=DecodeBlobEnvelope(context.Background(),streamPermit(t,authz.DefaultAdmissionLimits()),&staging,bytes.NewReader(encoded),id,streamSpec(len(payload),len(encoded),authz.AdmissionGZIP))
  if err!=nil || n!=uint64(len(payload)) || !bytes.Equal(staging.Bytes(),frame) { t.Fatalf("encoding changed identity: %d %v",n,err) }
 }
}

// Return one byte AND an error at the first deflate byte (after the default
// ten-byte gzip header). Even if the remaining bytes could decode successfully,
// the upstream error must prevent acceptance. This exercises IAM-10's inherited
// ReadByte adapter as used by the wrapper, rather than changing that adapter.
type streamDataErrorReader struct {
 data []byte
 offset int
 injected bool
 cause error
}
func (r *streamDataErrorReader) Read(p []byte) (int,error) {
 if len(p)==0 { return 0,nil }
 if r.offset==len(r.data) { return 0,io.EOF }
 if r.offset<10 && len(p)>10-r.offset { p=p[:10-r.offset] }
 if r.offset==10 && !r.injected {
  p[0]=r.data[r.offset]; r.offset++; r.injected=true
  return 1,r.cause
 }
 n:=copy(p,r.data[r.offset:]); r.offset+=n
 return n,nil
}
func TestBlobEnvelopeGZIPDataPlusError(t *testing.T) {
 payload:=[]byte("gzip data plus error must invalidate the complete frame")
 id,frame:=streamFrame(t,payload)
 encoded:=streamZip(t,frame,gzip.HuffmanOnly)
 cause:=errors.New("compressed source failed with data")
 in:=&streamDataErrorReader{data:encoded,cause:cause}
 n,err:=DecodeBlobEnvelope(context.Background(),streamPermit(t,authz.DefaultAdmissionLimits()),io.Discard,in,id,streamSpec(len(payload),len(encoded),authz.AdmissionGZIP))
 if !in.injected { t.Fatal("data-plus-error boundary not reached") }
 if n!=0 || !errors.Is(err,cause) { t.Fatalf("accepted source error: %d %v",n,err) }
}
