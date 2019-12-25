module symbol.demangler;

/// 
enum Language {
	C,
	Cpp,
	D
}

//const(char) *demangle(const(char) *symbol)