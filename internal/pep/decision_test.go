package pep

import (
	"context"
	"errors"
	"testing"
)

type deciderFunc func(context.Context, Input) (Decision, error)

func (f deciderFunc) Decide(ctx context.Context, in Input) (Decision, error) { return f(ctx, in) }

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		d       Decision
		wantErr bool
	}{
		{"allow", Decision{Effect: Allow}, false},
		{"deny", Decision{Effect: Deny}, false},
		{"ask", Decision{Effect: Ask, Ask: &AskSpec{Channel: ChannelURL}}, false},
		{"ask without spec", Decision{Effect: Ask}, true},
		{"ask unknown channel", Decision{Effect: Ask, Ask: &AskSpec{Channel: "carrier-pigeon"}}, true},
		{"empty effect", Decision{}, true},
		{"unknown effect", Decision{Effect: "maybe"}, true},
		{"version 1", Decision{Version: 1, Effect: Allow}, false},
		{"newer version", Decision{Version: 2, Effect: Allow}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.d.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestEvaluateFailsClosed(t *testing.T) {
	tests := []struct {
		name string
		d    Decider
		want Effect
	}{
		{"error", deciderFunc(func(context.Context, Input) (Decision, error) {
			return Decision{Effect: Allow}, errors.New("opa unreachable")
		}), Deny},
		{"invalid", deciderFunc(func(context.Context, Input) (Decision, error) {
			return Decision{Effect: "yes"}, nil
		}), Deny},
		{"allow", deciderFunc(func(context.Context, Input) (Decision, error) {
			return Decision{Effect: Allow}, nil
		}), Allow},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Evaluate(context.Background(), tt.d, Input{}); got.Effect != tt.want {
				t.Errorf("Evaluate() effect = %q, want %q", got.Effect, tt.want)
			}
		})
	}
}
