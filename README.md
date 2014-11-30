## paillier

Go implementation of the paillier cryptosystem and threshold paillier crytposystem.

#### introduction

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


#### caveat

As any cryptographic library, if you use it, you need to *trust* it.  Unfortunatly,
this library as not been verified by a third party.  There might be some bugs and
vulnerabilities.  If you find one, please fill a bug.

If you need to encrypt something serious, use the library provided by Go.  If you
want to have fun, use Paillier!
