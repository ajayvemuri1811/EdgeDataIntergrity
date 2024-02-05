//g++ -L/usr/include/botan-2/lib -I/usr/include/botan-2/include/botan-2/ -Wl,-rpath=/usr/include/botan-2/lib/ -Wall -o es2 edge_server_2.cpp -lbotan-2
//./es2

#include <bits/stdc++.h>

#include <botan/auto_rng.h>
#include <botan/rsa.h>
#include <botan/bigint.h>
#include <botan/hex.h>
#include <botan/hmac.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


using namespace std;

#define LINE_SIZE 3000
#define SERVER_PORT 6002


struct file {
	char name[LINE_SIZE];
};

struct challenge {
	char name[LINE_SIZE];
	char challenge[LINE_SIZE];
	char n[LINE_SIZE];
	char g[LINE_SIZE];
};

struct poi {
	char poi[LINE_SIZE];
};

struct message {
	int type;
	int size;
	file f;
	challenge c;
	poi p;
};

Botan::BigInt binpow(Botan::BigInt a, Botan::BigInt b) {
	Botan::BigInt res("1");
	
	if (a.is_zero()) return Botan::BigInt("0");
	
	while (Botan::BigInt("0").is_less_than(b)) {
		if (b.is_odd()){
			res.operator*=(a);
		}
			
		a.operator*=(a);
		b.operator>>=(1);
	}
	
	return res;
}


Botan::BigInt binpowmod(Botan::BigInt a, Botan::BigInt b, Botan::BigInt p) {
	Botan::BigInt res("1");
	
	a.operator%=(p);
	
	
	if (a.is_zero()) return Botan::BigInt("0");
	
	while (Botan::BigInt("0").is_less_than(b)) {
		if (b.is_odd()){
			res.operator*=(a);
			res.operator%=(p);
		}
			
		a.operator*=(a);
		a.operator%=(p);
		b.operator>>=(1);
	}
	
	return res;
}

string convert_to_bitstring1024(string str) 
{
	while (str.size() != 128) {
		str = str + '0';
	}

	string bit_string = "";

	for (long unsigned int i = 0; i < str.length(); ++i) {
        bitset<8> bs4(str[i]);

        for ( long int j = 7; j >= 0 ; --j ) {
        	if (bs4[j] == 1) {
        		bit_string  += '1';
        	} else {
        		bit_string  += '0';
        	}
        }
    }

    return bit_string;
}


string convert_to_4bitstring(string str) 
{

	string bit_string = "";

	for (long unsigned int i = 0; i < str.length(); ++i) {
        bitset<4> bs4(str[i]);

        for ( long int j = 3; j >= 0 ; j-- ) {
        	if (bs4[j] == 1) {
        		bit_string  += '1';
        	} else {
        		bit_string  += '0';
        	}
        }
    }

    return bit_string;
}


Botan::BigInt convert_datablock_to_number1024( string bit_string ) {
	
	Botan::BigInt two("2");
	Botan::BigInt pow("0");
	Botan::BigInt ans("0");
	for ( int i = bit_string.size() - 1; i >= 0; i--   ) {
		if ( bit_string[i] == '1' ) {
			ans.operator+=(binpow(two, pow));
		}

		pow.operator+=(1);
	}

	return ans;
}

string read_file_data (string filename) { // newlines are ignored

	fstream myfile;
 
    myfile.open(filename);
    vector<string> data;
    string con_data = "";
 
    if (myfile.is_open()) {

        string str;

        while (getline(myfile, str)) {
            data.push_back(str);
        }
        
        myfile.close();
    }

    cout << endl;
    for ( long unsigned int  i = 0 ; i < data.size(); i++ ) {

    	for ( long unsigned int j = 0 ; j < data[i].size() - 1; j++ ){
    		con_data += data[i][j];
    	}
    }

    // cout << con_data <<" "<<con_data.size()<<"\n";
    return con_data;

}

vector<Botan::BigInt> convert_file_to_numarray(string filename) {

	vector<Botan::BigInt> file_data;
	string data;
	long unsigned int i = 0;
	string temp = "";

	data = read_file_data(filename);


	while ( i < data.size() ) {
		temp = temp + data[i];
		if (temp.size() == 128 || i == data.size() - 1 ) {
			string bit_string = convert_to_bitstring1024(temp);
			// cout << bit_string <<"\n\n";
			file_data.push_back(convert_datablock_to_number1024(bit_string));
			temp  = "";
		}
		i++;
	}

	return file_data;
}


vector<Botan::BigInt> calculate_tags (Botan::BigInt g, vector<Botan::BigInt> file_data , Botan::BigInt n) {

	vector<Botan::BigInt> homomorphic_tags;

	for ( long unsigned int  i = 0 ; i < file_data.size(); i++ ) {
		// cout << numeric_data[i] <<"\n";

		homomorphic_tags.push_back(binpowmod(g, file_data[i], n ));
	}

	return homomorphic_tags;

}

set<int> calculate_indices (Botan::BigInt challenge, int len) {

	int counter = 0;
	string message;
	set<int> indices;
	string temp = "";

	while ( int(indices.size()) < (len/10) + 1  ) {
		counter++;
		message = to_string(counter);
		temp = challenge.to_dec_string();
		Botan::OctetString key(temp.substr(0,32));
		auto hmac = Botan::MessageAuthenticationCode::create_or_throw("HMAC(SHA-256)");
	  	hmac->set_key(key);
	  	hmac->update(message);
	  	string mac_digest = Botan::hex_encode(hmac->final());
	  	mac_digest = convert_to_4bitstring(mac_digest);
	  	indices.insert(convert_datablock_to_number1024(mac_digest).operator%=(Botan::BigInt(len)).to_u32bit() );
	}

	return indices;

}


Botan::BigInt calculate_poi( Botan::BigInt challenge, vector<Botan::BigInt> tags, Botan::BigInt n ) {

	Botan::BigInt poi("1");

	set<int> indices = calculate_indices(challenge, tags.size());


	for ( auto x : indices ) {
		poi.operator*=(tags[x]);
		poi.operator%=(n);
	}

	return poi;

}

// void recv_file (struct message &m, int sockfd, struct sockaddr_in service_vendor_addr) {

// 	cout << m.type << "\n";
// 	cout << m.f.name <<"\n";


// 	std::ofstream fp(m.f.name);

//     char buf[100];
//     memset(buf, '\0', 100);
//     socklen_t server_len = sizeof(service_vendor_addr);

//     while (strcmp(buf, "file_complete_") != 0) {
//         memset(buf, '\0', 100);
//         recvfrom(sockfd, buf, 100, 0, (struct sockaddr*)&service_vendor_addr, &server_len);
//         std::cout << "\nData received: " << buf << std::endl;
//         if (strcmp(buf, "file_complete_") != 0) {
//             fp << buf;
//         }
//     }

//     fp.close();
 
// 	return;
// }

void check_integrity (struct message &m, int sockfd, struct sockaddr_in service_vendor_addr) {
	
	string filename = m.c.name;
	Botan::BigInt challenge(m.c.challenge);
	Botan::BigInt n(m.c.n);
	Botan::BigInt g(m.c.g);


	vector<Botan::BigInt> file_data; // contains data fo the required file in numeric form of 1KB blocks.
	vector<Botan::BigInt> tags; // contains tags for each data block
	Botan::BigInt poi; // POI for the given challenge

	cout <<"Checking integrity for file : "<<filename<<"....\n\n";

	// Convert file to numeric data of 1KB block size
	file_data = convert_file_to_numarray(filename);
	cout <<"\tFile data converted to numeric blocks...\n\n";

	//Calculate Tags for each block
	tags = calculate_tags(g, file_data, n);
	cout <<"\tHomomorphic tags calulated for the file....\n\n";


	//Calculating poi for the given challenge
	poi = calculate_poi(challenge, tags, n);
	cout <<"\tCalculated poi for the given challnege....\n\n";
	// cout << poi << "\n\n";


	struct poi p;
	memset(&p, '\0', sizeof(p));
	strcpy(p.poi, poi.to_dec_string().c_str());

	message mes;
	mes.type = 3;
	mes.size = sizeof(p);
	mes.p = p;


	sendto(sockfd, &mes, sizeof(mes), MSG_CONFIRM, (const struct sockaddr *) &service_vendor_addr, sizeof(service_vendor_addr));

	cout <<"\tSent response to the challenge....\n\n";

}


int start_server() 
{

    int sockfd;
    struct sockaddr_in servaddr;

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
            perror("socket creation failed.");
            exit(EXIT_FAILURE);
    }

    memset(&servaddr, 0, sizeof(servaddr));


    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(SERVER_PORT);
    servaddr.sin_addr.s_addr = INADDR_ANY;


    if (bind(sockfd, (const struct sockaddr*) &servaddr, sizeof(servaddr)) < 0) {
            perror("bind failed.");
            exit(EXIT_FAILURE);
    } else {
    	cout << "Server listening at port " << SERVER_PORT <<"...\n\n";
    }

    return sockfd;

}


void listen1(int sockfd) {

    while(1) {

        struct message m;
        socklen_t len;
        struct sockaddr_in service_vendor_addr;

        len = sizeof(service_vendor_addr);

        memset(&service_vendor_addr, 0, sizeof(service_vendor_addr));

        recvfrom( sockfd, &m, sizeof(struct message), MSG_WAITALL, ( struct sockaddr *) &service_vendor_addr, &len );

        if ( m.type == 2) {
        	check_integrity(m, sockfd, service_vendor_addr);
        } else {
        	cout << "\tInvalid message received...\n\n";
        }
    }

}

int main() {

	int sockfd;


	sockfd = start_server();

	listen1(sockfd);

	return 0;
}