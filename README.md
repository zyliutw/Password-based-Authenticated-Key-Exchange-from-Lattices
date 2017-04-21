# Lattice-Based-PAKE-Key-Exchange

## Introduction
> This project implement Lattice Based PAKE Key Exchange based on 

## Project Structure
```
Lattice-Based-PAKE-Key-Exchange
  |-- Client_Desktop : Client for Desktop
  |-- Client_Phone : Client for Android
  |-- Server  : Server side
```

## Run
#### All projects are able to be build with gradle
#### Step 1 
Run Server with tomcat first
#### Step 2
Set up idc_pw_map table in Server project (Index.java)<br>
Run Server with Tomcat
#### Step 3
Set up Server url in Desktop / Phone (HttpUtil.java)<br>
Run and set idc / pw / ids / g , then you can get the same secret sharing key in server/ client side


## License
This project follows NTRU open source project, use GPLv3 License

## Library Reference
1. [NTRUEncrypt](https://github.com/NTRUOpenSourceProject/ntru-crypto)
2. [Java Lattice Based Cryptography Library (jLBC)](http://gas.dia.unisa.it/projects/jlbc/)
3. [Java Pairing Based Cryptography Library (JPBC)](http://gas.dia.unisa.it/projects/jpbc/#.WPhieVOGOV4)
