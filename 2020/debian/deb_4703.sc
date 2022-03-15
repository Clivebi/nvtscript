if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704703" );
	script_version( "2021-07-26T02:01:39+0000" );
	script_cve_id( "CVE-2020-2875", "CVE-2020-2933", "CVE-2020-2934" );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-26 02:01:39 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-26 12:15:00 +0000 (Wed, 26 May 2021)" );
	script_tag( name: "creation_date", value: "2020-06-12 03:00:11 +0000 (Fri, 12 Jun 2020)" );
	script_name( "Debian: Security Advisory for mysql-connector-java (DSA-4703-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2020/dsa-4703.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4703-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mysql-connector-java'
  package(s) announced via the DSA-4703-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Three vulnerabilities have been found in the MySQL Connector/J JDBC
driver." );
	script_tag( name: "affected", value: "'mysql-connector-java' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the oldstable distribution (stretch), these problems have been fixed
in version 5.1.49-0+deb9u1.

We recommend that you upgrade your mysql-connector-java packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libmysql-java", ver: "5.1.49-0+deb9u1", rls: "DEB9" ) )){
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
exit( 0 );

