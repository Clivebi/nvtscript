if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891418" );
	script_version( "2021-06-17T02:00:27+0000" );
	script_cve_id( "CVE-2016-1000338", "CVE-2016-1000339", "CVE-2016-1000341", "CVE-2016-1000342", "CVE-2016-1000343", "CVE-2016-1000345", "CVE-2016-1000346" );
	script_name( "Debian LTS: Security Advisory for bouncycastle (DLA-1418-1)" );
	script_tag( name: "last_modification", value: "2021-06-17 02:00:27 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-07-10 00:00:00 +0200 (Tue, 10 Jul 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-20 22:15:00 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/07/msg00009.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "bouncycastle on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
1.49+dfsg-3+deb8u3.

We recommend that you upgrade your bouncycastle packages." );
	script_tag( name: "summary", value: "Several security vulnerabilities were found in Bouncy
Castle, a Java implementation of cryptographic algorithms.

CVE-2016-1000338
DSA does not fully validate ASN.1 encoding of signature on
verification. It is possible to inject extra elements in the
sequence making up the signature and still have it validate, which
in some cases may allow the introduction of 'invisible' data into a
signed structure.

CVE-2016-1000339
Previously the primary engine class used for AES was AESFastEngine.
Due to the highly table driven approach used in the algorithm it
turns out that if the data channel on the CPU can be monitored the
lookup table accesses are sufficient to leak information on the AES
key being used. There was also a leak in AESEngine although it was
substantially less. AESEngine has been modified to remove any signs
of leakage and is now the primary AES class for the BC JCE provider.
Use of AESFastEngine is now only recommended where otherwise deemed
appropriate.

CVE-2016-1000341
DSA signature generation is vulnerable to timing attack. Where
timings can be closely observed for the generation of signatures,
the lack of blinding may allow an attacker to gain information about
the signature's k value and ultimately the private value as well.

CVE-2016-1000342
ECDSA does not fully validate ASN.1 encoding of signature on
verification. It is possible to inject extra elements in the
sequence making up the signature and still have it validate, which
in some cases may allow the introduction of 'invisible' data into a
signed structure.

CVE-2016-1000343
The DSA key pair generator generates a weak private key if used with
default values. If the JCA key pair generator is not explicitly
initialised with DSA parameters, 1.55 and earlier generates a
private value assuming a 1024 bit key size. In earlier releases this
can be dealt with by explicitly passing parameters to the key pair
generator.

CVE-2016-1000345
The DHIES/ECIES CBC mode is vulnerable to padding oracle attack. In
an environment where timings can be easily observed, it is possible
with enough observations to identify when the decryption is failing
due to padding.

CVE-2016-1000346
In the Bouncy Castle JCE Provider the other party DH public key is
not fully validated. This can cause issues as invalid keys can be
used to reveal details about the other party's private key where
static Diffie-Hellman is in use. As of this release the key
parameters are checked on agreement calculation." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libbcmail-java", ver: "1.49+dfsg-3+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libbcmail-java-doc", ver: "1.49+dfsg-3+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libbcpg-java", ver: "1.49+dfsg-3+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libbcpg-java-doc", ver: "1.49+dfsg-3+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libbcpkix-java", ver: "1.49+dfsg-3+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libbcpkix-java-doc", ver: "1.49+dfsg-3+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libbcprov-java", ver: "1.49+dfsg-3+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libbcprov-java-doc", ver: "1.49+dfsg-3+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if( report != "" ){
	security_message( data: report );
}
else {
	if(__pkg_match){
		exit( 99 );
	}
}

