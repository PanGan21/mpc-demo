package ecdsa

import (
	"fmt"
	"math/big"
)

// Point represents an elliptic curve point
type Point struct {
	X *big.Int
	Y *big.Int
}

// NewPoint creates a new point
func NewPoint(x, y *big.Int) *Point {
	return &Point{X: x, Y: y}
}

// IsZero checks if the point is the point at infinity (identity)
func (p *Point) IsZero() bool {
	return p.X == nil || p.Y == nil
}

// String returns a string representation of the point
func (p *Point) String() string {
	if p.IsZero() {
		return "(∞)"
	}
	return fmt.Sprintf("(x=%s, y=%s)", p.X.String(), p.Y.String())
}

// Copy returns a copy of the point
func (p *Point) Copy() *Point {
	if p.IsZero() {
		return &Point{}
	}
	return &Point{
		X: new(big.Int).Set(p.X),
		Y: new(big.Int).Set(p.Y),
	}
}

// Equal checks if two points are equal
func (p *Point) Equal(other *Point) bool {
	if p.IsZero() && other.IsZero() {
		return true
	}
	if p.IsZero() || other.IsZero() {
		return false
	}
	return p.X.Cmp(other.X) == 0 && p.Y.Cmp(other.Y) == 0
}



