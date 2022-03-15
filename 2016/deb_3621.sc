if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703621" );
	script_version( "$Revision: 14275 $" );
	script_cve_id( "CVE-2015-2575" );
	script_name( "Debian Security Advisory DSA 3621-1 (mysql-connector-java - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-07-18 00:00:00 +0200 (Mon, 18 Jul 2016)" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:N" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3621.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "mysql-connector-java on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
this problem has been fixed in version 5.1.39-1~deb8u1.

We recommend that you upgrade your mysql-connector-java packages." );
	script_tag( name: "summary", value: "A vulnerability was discovered in
mysql-connector-java, a Java database (JDBC) driver for MySQL, which may result
in unauthorized update, insert or delete access to some MySQL Connectors
accessible data as well as read access to a subset of MySQL Connectors accessible
data. The vulnerability was addressed by upgrading mysql-connector-java to the new
upstream version 5.1.39, which includes additional changes, such as bug
fixes, new features, and possibly incompatible changes." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libmysql-java", ver: "5.1.39-1~deb8u1", rls: "DEB8" ) ) != NULL){
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

