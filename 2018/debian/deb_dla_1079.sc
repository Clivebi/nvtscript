if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891079" );
	script_version( "2021-06-18T02:00:26+0000" );
	script_cve_id( "CVE-2015-3152", "CVE-2017-10788", "CVE-2017-10789" );
	script_name( "Debian LTS: Security Advisory for libdbd-mysql-perl (DLA-1079-1)" );
	script_tag( name: "last_modification", value: "2021-06-18 02:00:26 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-07 00:00:00 +0100 (Wed, 07 Feb 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-12 18:24:00 +0000 (Wed, 12 Jul 2017)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/08/msg00033.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "libdbd-mysql-perl on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
4.021-1+deb7u3.

We recommend that you upgrade your libdbd-mysql-perl packages." );
	script_tag( name: "summary", value: "The Perl library for communicating with MySQL database, used in the
'mysql' commandline client is vulnerable to a man in the middle attack
in SSL configurations and remote crash when connecting to hostile
servers.

CVE-2017-10788

The DBD::mysql module through 4.042 for Perl allows remote
attackers to cause a denial of service (use-after-free and
application crash) or possibly have unspecified other impact by
triggering (1) certain error responses from a MySQL server or (2)
a loss of a network connection to a MySQL server. The
use-after-free defect was introduced by relying on incorrect
Oracle mysql_stmt_close documentation and code examples.

CVE-2017-10789

The DBD::mysql module through 4.042 for Perl uses the mysql_ssl=1
setting to mean that SSL is optional (even though this setting's
documentation has a 'your communication with the server will be
encrypted' statement), which allows man-in-the-middle attackers to
spoof servers via a cleartext-downgrade attack, a related issue to
CVE-2015-3152." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libdbd-mysql-perl", ver: "4.021-1+deb7u3", rls: "DEB7" ) )){
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

