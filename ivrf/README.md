# iVRF

This is the implementation source code (using the Falcon signature) for the paper:

Muhammed F. Esgin, Oğuzhan Ersoy, Veronika Kuchta, Julian Loss, Amin Sakzad, Ron Steinfeld, Wayne Yang, & Raymond K. Zhao. (2023). A New Look at Blockchain Leader Election: Simple, Efficient, Sustainable and Post-Quantum. Proceedings of AsiaCCS 2023. DOI [10.1145/3579856.3595792](https://doi.org/10.1145/3579856.3595792).

@inproceedings{DBLP:conf/asiaccs/EsginEKLSSYZ23,
  author       = {Muhammed F. Esgin and
                  Oguzhan Ersoy and
                  Veronika Kuchta and
                  Julian Loss and
                  Amin Sakzad and
                  Ron Steinfeld and
                  Xiangwen Yang and
                  Raymond K. Zhao},
  title        = {A New Look at Blockchain Leader Election: Simple, Efficient, Sustainable
                  and Post-Quantum},
  booktitle    = {AsiaCCS},
  pages        = {623--637},
  publisher    = {{ACM}},
  year         = {2023}
}

To compile the source code:

1. Run `make ivrf` to compile the source code.

2. Run `./ivrf` to start the benchmark. The two values on the first line are the runtime (in CPU cycles) of iAV.Keygen and the total (N) Σ.Keygen (step 5) runtime in iAV.Keygen, respectively. Each of the following 2000 lines has 6 values, which are the runtime (in CPU cycles) of iAV.Eval, Σ.Keygen (step 4) in iAV.Eval, Σ.Sign (step 5) in iAV.Eval, iAV.Verify, Σ.Verify (step 3) in iAV.Verify, and the return value of iAV.Verify, respectively. Line 2--1001 are j=0, and Line 1002--2001 are j=t-1. 

The variant using the XMSS signature is under the "[xmss](https://gitlab.com/raykzhao/ivrf/-/tree/xmss)" branch. 
