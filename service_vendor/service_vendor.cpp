//g++ -L/usr/include/botan-2/lib -I/usr/include/botan-2/include/botan-2/ -Wl,-rpath=/usr/include/botan-2/lib/ -Wall -o sv service_vendor.cpp -lbotan-2
//./sv
// edge_server2/127.0.0.1/6002
// edge_server3/127.0.0.1/6003
// edge_server4/127.0.0.1/6004
// edge_server5/127.0.0.1/6005


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
#define SERVER_PORT 8008


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

map<string, pair<string, int>> edge_servers;


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


Botan::BigInt gcd(Botan::BigInt a, Botan::BigInt b)
{
    if (a.is_zero())
        return b;
    return gcd(b.operator%=(a), a);
}


int get_edge_server_data()
{
	FILE *fp;
	char buffer[LINE_SIZE];
	int num_of_edge_servers = 0;
	int col_count = 0;
	string edge_name = "";
	string edge_ip = "";
	int edge_port = 0; 


	//Opening the file
    fp = fopen("sv_list.txt", "r");
	if (!fp) {
        printf("Error, Can't Open file\n");
        return -1;
    }


    while (fgets(buffer, LINE_SIZE, fp)) {


    	num_of_edge_servers++;
    	col_count++;


    	char* token = strtok(buffer, "/");

    	while (token != NULL) {

    		if ( col_count == 1 ) {
    			edge_name  = token;
    		} else if ( col_count  == 2 ) {
    			edge_ip = token;
    		} else {
    			edge_port = atoi(token);
    		}

    		col_count++;
        	token = strtok(NULL, "/");
    	}

    	// cout << edge_name <<" "<<edge_ip<<" "<<edge_port<<"\n";

    	edge_servers[edge_name] = {edge_ip, edge_port};

    	col_count = 0;

    }

    fclose(fp);

    return num_of_edge_servers;

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
    }

    return sockfd;

}


void send_file(int sockfd) {  // will see it later
	return;
}


vector<pair<Botan::BigInt, Botan::BigInt>> key_generation (int k) { 

	Botan::AutoSeeded_RNG rngA;
	bool flag;
	Botan::BigInt p;
	Botan::BigInt q;
	Botan::BigInt n;
	Botan::BigInt g;
	vector<pair<Botan::BigInt, Botan::BigInt>> keys;


	Botan::RSA_PrivateKey private_key(rngA, k);


	p = private_key.get_p();
	q = private_key.get_q();
	n = private_key.get_n();

	flag = 1;
	while ( flag ) {
		g = Botan::BigInt::random_integer(rngA, 2, n - 1);
		if (( gcd ( g.operator+=(1), n ) == 1 ) && ( gcd ( g.operator-=(1), n ) == 1 )) {
			g.operator*=(g);
			flag = 0;
		}
	}


	keys.push_back({n, g});
	keys.push_back({p, q});

	return keys;
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


vector<Botan::BigInt> calculate_challenges ( int k  , int num_of_edge_servers) {

	Botan::AutoSeeded_RNG rngA;
	vector<Botan::BigInt> challenges;
	Botan::BigInt exp(k);
	Botan::BigInt two("2");
	Botan::BigInt max_limit  = (binpow(two, exp));
	max_limit.operator--();



	for ( int i = 0; i < num_of_edge_servers ; i++ ) {
		challenges.push_back(Botan::BigInt::random_integer(rngA, 2, max_limit));
	}

	return challenges;

}

//send challenges and recv pois
vector<Botan::BigInt> send_challenges (int sockfd, string filename, vector<Botan::BigInt> challenges, pair<Botan::BigInt, Botan::BigInt> keys) { // we will see later
	
	vector<Botan::BigInt> received_pois;
	int counter = 0;

	for ( auto x : edge_servers ) {

		struct challenge c;
		memset(&c, '\0', sizeof(c));
		strcpy(c.name, filename.c_str());
		strcpy(c.challenge, challenges[counter].to_dec_string().c_str());
		strcpy(c.n, keys.first.to_dec_string().c_str());
		strcpy(c.g, keys.second.to_dec_string().c_str());

		struct message m;
		m.type = 2;
		m.size = sizeof(c);
		m.c = c;

		struct sockaddr_in	 servaddr;

        servaddr.sin_family = AF_INET;
        servaddr.sin_port = htons(x.second.second);
        char* ip = const_cast<char*>(x.second.first.c_str());
        servaddr.sin_addr.s_addr = inet_addr(ip);

        sendto(sockfd, &m, sizeof(m), MSG_CONFIRM, (const struct sockaddr *) &servaddr, sizeof(servaddr));


        struct message res;
        socklen_t len;
        struct sockaddr_in edge_server_addr;

        len = sizeof(edge_server_addr);

        memset(&edge_server_addr, 0, sizeof(edge_server_addr));

        recvfrom( sockfd, &res, sizeof(struct message), MSG_WAITALL, ( struct sockaddr *) &edge_server_addr, &len );
        // cout << res.type <<"\n";
        // cout << res.p.poi <<"\n";

        received_pois.push_back(Botan::BigInt (res.p.poi));

		counter++;
	}


	return received_pois;
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

void binary_search ( vector<Botan::BigInt> received_pois, vector<Botan::BigInt> calculated_pois, int l, int r, Botan::BigInt n, vector<bool> &result ) {

	Botan::BigInt R ("1");
	Botan::BigInt R_ ("1");
	// cout << l << " " << r << "\n";


	if ( l < r  ) {
		for ( int i = l ; i <= r; i++ ) {
			R.operator*=(received_pois[i]);
			R.operator%=(n);
			R_.operator*=(calculated_pois[i]);
			R_.operator%=(n);
		}

		if ( R.is_equal(R_) ) {
			for ( int i = l ; i <= r; i++ ) {
				result[i] = false;
			}
		} else {
			int mid = ( l + r ) >> 1;
			binary_search(received_pois, calculated_pois, l, mid, n,  result);
			binary_search(received_pois, calculated_pois, mid + 1, r, n,  result);

		}		
	} else if ( l == r ){
		if ( received_pois[l].is_equal(calculated_pois[l]) ) {
			result[l] = false;
		}
	} else {
		return;
	}


}


void check_integrity_utility(int sockfd) {

	int k = 1024;
	int num_of_edge_servers;
	string filename;
	vector<pair<Botan::BigInt, Botan::BigInt>> keys; //0 is public key 1 is private key
	vector<Botan::BigInt> file_data; // contains data fo the required file in numeric form of 1KB blocks.
	vector<Botan::BigInt> tags; // contains tags for each data block
	vector<Botan::BigInt> challenges; // contains challenges for the edge servers
	vector<Botan::BigInt> received_pois; // contains poi from edges servers for their respective challenges
	vector<Botan::BigInt> calculated_pois; // contains pois for each challenge as calculted by service vendor
	vector<bool> result;
	bool flag;
 
	num_of_edge_servers = get_edge_server_data();
	result.resize(num_of_edge_servers, true);


	cout << "\tEnter the file name to be checked:\n\t";
	cin >> filename;


	// Generate keys for the checking
	keys = key_generation(k);
	cout <<"\n\tKeys Generated...\n";


	// Convert file to numeric data of 1KB block size
	file_data = convert_file_to_numarray(filename);
	cout <<"\tFile data converted to numeric blocks...\n\n";


	//Calculate Tags for each block
	tags = calculate_tags(keys[0].second, file_data, keys[0].first);
	cout <<"\tHomomorphic tags calulated for the file....\n\n";


	//Generating challenges for the edge servers
	challenges = calculate_challenges(k, num_of_edge_servers);
	cout <<"\tGenerated challenges for the edge servers....\n\n";


	//Send challenges to edges servers with public key
	received_pois = send_challenges(sockfd, filename, challenges, keys[0]);
	cout <<"\tReceived poi's from all edge servers....\n\n";


	//For each challenge get proof of integrity
	for ( int i = 0; i < num_of_edge_servers ; i++ ) {
		calculated_pois.push_back(calculate_poi(challenges[i], tags, keys[0].first));
		// if ( i % 2 )
		// received_pois.push_back(calculate_poi(challenges[i], tags, keys[0].first).operator+=(Botan::BigInt("1")));
		// else
		// received_pois.push_back(calculate_poi(challenges[i], tags, keys[0].first)); // change it
	}
	cout <<"\tCalculated correct poi's for each edge server....\n\n";


	// Find and localize corrupted edge data replicas
	binary_search(received_pois, calculated_pois, 0, calculated_pois.size() - 1, keys[0].first,  result);
	cout <<"\tCompared received results with calulated pois....\n\n";


	for ( int i = 0; i < num_of_edge_servers ; i++ ) {
		if ( result[i] == true )
			flag = true;
	}


	if ( flag == false ) {
		cout <<"\tAll data replicas of the given file are correct and up to date.\n\n";
	} else {
		cout <<"\tName and ip addresses of edge servers having corrupted data replicas are:\n\n";
		int temp = 0;
		for ( auto x : edge_servers ) {
			if ( result[temp] == true ) {
				cout <<"\t"<< x.first <<" "<< x.second.first<<"::"<<x.second.second<<"\n\n";
			}

			temp++;
		}
	}



	return;
}



int main() {

	int sockfd;
	int option;


	sockfd = start_server();


	while ( 1 ) {
		cout << "Choose the action you want to perform....."<<"\n";
		cout << "1 :: Send a file to all edge servers."<<"\n";
		cout << "2 :: Check integrity of a file in edge servers."<<"\n";
		cout << "3 :: EXIT"<<"\n";
		cin >> option;

		if ( option != 1 && option != 2 )
			break;
		else {
			switch ( option ) {
				case 1 : send_file(sockfd);
					break;
				case 2 : check_integrity_utility(sockfd);
					break;
				default : break;
			}
		}

	}

	return 0;
}