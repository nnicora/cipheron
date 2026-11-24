package client

import (
	"sync"
	"testing"
	"time"
)

// TestAListStampedConcurrentlyIsNeverInTheFuture: a fetch completed by another call stamps the list as verified while
// this call measures its age. The age is measured from the stamp read first and the clock read after it, so it is
// never negative on a monotonic clock — a negative age is "no usable age" (fail closed), and Sign would fetch the keys
// a second time (TestASigningRotationIsAdopted's "2 PublicKey calls"). Read the other way round, a stamp landing
// between the two reads is in the future of the instant measured from.
func TestAListStampedConcurrentlyIsNeverInTheFuture(t *testing.T) {
	var f freshness
	f.verifiedAt(time.Now())
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { // another call's fetches, completing one after the other
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				f.verifiedAt(time.Now())
			}
		}
	}()
	defer func() { close(stop); wg.Wait() }()
	for i := range 200000 {
		if age, known := f.age(time.Now); !known {
			t.Fatalf("read %d: a list stamped by a concurrent fetch has no usable age (%v)", i, age)
		}
	}
}

// TestAnAgeFromAClockBehindTheStampIsNotKnown: a clock that reads earlier than the stamp (not monotonic) gives no
// usable age — the list is treated as stale, never as fresh.
func TestAnAgeFromAClockBehindTheStampIsNotKnown(t *testing.T) {
	var f freshness
	if _, known := f.age(time.Now); known {
		t.Fatal("a list never verified has an age")
	}
	at := time.Now()
	f.verifiedAt(at)
	if _, known := f.age(func() time.Time { return at.Add(-time.Second) }); known {
		t.Fatal("a clock behind the stamp gave a usable age")
	}
	if age, known := f.age(func() time.Time { return at.Add(time.Minute) }); !known || age != time.Minute {
		t.Fatalf("a minute after the stamp: %v %v", age, known)
	}
}
