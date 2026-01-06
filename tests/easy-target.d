module tests.easy.target;

extern (C):

void main() {
	void function() bad;
	bad();
}