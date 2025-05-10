#ifndef __PBC_EXCEPTIONS_H__
#define __PBC_EXCEPTIONS_H__

#include <stdexcept>

namespace PBC {

using namespace std;

class PBCException : public runtime_error {
public:
  PBCException(const string &str = "") : runtime_error("PBC Exception: " + str) {}
};

class UndefinedPairingException : public PBCException {
public:
  UndefinedPairingException() : PBCException("Pairing is not defined.") {}
};

class UndefinedElementException : public PBCException {
public:
  UndefinedElementException() : PBCException("Element is not defined.") {}
};

class CorruptDataException : public PBCException {
public:
  CorruptDataException()
      : PBCException("Data buffer for an element import is corrupt.") {}
};

class NonsymmetricPairingException : public PBCException {
public:
  NonsymmetricPairingException() : PBCException("Pairing is not symmetric.") {}
};

} // namespace PBC

#endif
