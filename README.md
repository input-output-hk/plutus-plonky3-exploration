# plutus-plonky3-exploration

Explorations and prototypes for verifying Plonky3 STARK proofs on Cardano.

> ### ⚠️ Important Disclaimer & Acceptance of Risk
>
> **This repository contains prototype implementations.** This code is provided "as is" for research and educational purposes 
> only. It has not been thoroughly tested and audited and is not intended for production use. By using this code, you 
> acknowledge and accept all associated risks, and our company disclaims any liability for damages or losses.

## Intent

[Plonky3](https://github.com/Plonky3/Plonky3) is a modular, production-grade STARK framework — the backbone of SP1 zkVM.

This repository investigates whether Plonky3 proofs can be verified on Cardano within Plutus execution limits, using existing builtins (blake2b, integer arithmetic).

Cardano's current ZK path (Groth16/PLONK over BLS12-381) is pairing-based and therefore vulnerable to quantum attacks. STARKs are mature post-quantum alternative — they rely only on hash functions and field arithmetic, no elliptic curves — so the open question is whether a STARK verifier fits inside Plutus. This is a feasibility study, not a production verifier: the aim is concrete cost numbers and a gap analysis (which builtins, limit increases, or multi-tx patterns would be needed). See [docs/proposal-plonky3-stark-verification-on-cardano.md](docs/proposal-plonky3-stark-verification-on-cardano.md) for the full motivation.

## License

Copyright 2026 Input Output Global

Licensed under the Apache License, Version 2.0 (the "License"). You may not use this repository except in compliance
with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an 
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
language governing permissions and limitations under the License