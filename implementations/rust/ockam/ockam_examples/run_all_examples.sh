#!/usr/bin/env bash
for e in examples/*.rs; do
  cargo run --example `basename $e .rs`;
done
