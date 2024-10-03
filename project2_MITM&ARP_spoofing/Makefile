all: mitm_attack pharm_attack

mitm_attack: mitm_attack.c
	g++ $^ -o $@ -pthread

pharm_attack: pharm_attack.c
	g++ $^ -o $@ -pthread

clean:
	rm -f mitm_attack pharm_attack
