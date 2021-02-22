#!/usr/bin/env bash
for e in examples/node*.rs; do
  cargo run --example `basename $e .rs`;
done
