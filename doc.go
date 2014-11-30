//The MIT License (MIT)

//Copyright (c) 2013 didier amyot

//Permission is hereby granted, free of charge, to any person obtaining a copy
//of this software and associated documentation files (the "Software"), to deal
//in the Software without restriction, including without limitation the rights
//to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//copies of the Software, and to permit persons to whom the Software is
//furnished to do so, subject to the following conditions:

//The above copyright notice and this permission notice shall be included in
//all copies or substantial portions of the Software.

//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//THE SOFTWARE.

/*
Implementation of the paillier cryptosystem.  See
http://en.wikipedia.org/wiki/Paillier_cryptosystem for an introduction.

The threshold paillier cryptosystem is a translation of the java version
that can be found at http://cs.utdallas.edu/dspl/cgi-bin/pailliertoolbox/ that
is an implementation of the algorithm defined in Damgård's paper
"A Generalization of Paillier's Public-Key System with Applications to
Electronic Voting".

Another important feature of the library is the ease of serilisation of all
the structs in JSON and BSON.

Implements the paillier cryptosystem and threshold paillier crytposystem.
*/
package paillier
