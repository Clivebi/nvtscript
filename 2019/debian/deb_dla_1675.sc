if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891675" );
	script_version( "2021-09-03T14:02:28+0000" );
	script_cve_id( "CVE-2019-6690" );
	script_name( "Debian LTS: Security Advisory for python-gnupg (DLA-1675-1)" );
	script_tag( name: "last_modification", value: "2021-09-03 14:02:28 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-02-14 00:00:00 +0100 (Thu, 14 Feb 2019)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-13 04:15:00 +0000 (Mon, 13 Jul 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/02/msg00021.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "python-gnupg on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
0.3.6-1+deb8u1.

We recommend that you upgrade your python-gnupg packages." );
	script_tag( name: "summary", value: "Alexander Kj?ll and Stig Palmquist discovered a vulnerability in
python-gnupg, a wrapper around GNU Privacy Guard. It was possible to
inject data through the passphrase property of the gnupg.GPG.encrypt()
and gnupg.GPG.decrypt() functions when symmetric encryption is used.
The supplied passphrase is not validated for newlines, and the library
passes --passphrase-fd=0 to the gpg executable, which expects the
passphrase on the first line of stdin, and the ciphertext to be
decrypted or plaintext to be encrypted on subsequent lines.

By supplying a passphrase containing a newline an attacker can
control/modify the ciphertext/plaintext being decrypted/encrypted." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "python-gnupg", ver: "0.3.6-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3-gnupg", ver: "0.3.6-1+deb8u1", rls: "DEB8" ) )){
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

