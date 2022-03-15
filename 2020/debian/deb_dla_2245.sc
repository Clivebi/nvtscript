if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892245" );
	script_version( "2021-07-27T02:00:54+0000" );
	script_cve_id( "CVE-2020-2875", "CVE-2020-2933", "CVE-2020-2934" );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-27 02:00:54 +0000 (Tue, 27 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-26 12:15:00 +0000 (Wed, 26 May 2021)" );
	script_tag( name: "creation_date", value: "2020-06-12 03:00:10 +0000 (Fri, 12 Jun 2020)" );
	script_name( "Debian LTS: Security Advisory for mysql-connector-java (DLA-2245-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/06/msg00015.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2245-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mysql-connector-java'
  package(s) announced via the DLA-2245-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several issues were discovered in mysql-connector-java, a Java database
(JDBC) driver for MySQL, that allow attackers to update, insert or
delete access to some of MySQL Connectors accessible data, unauthorized
read access to a subset of the data, and partial denial of service." );
	script_tag( name: "affected", value: "'mysql-connector-java' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
5.1.49-0+deb8u1.

We recommend that you upgrade your mysql-connector-java packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libmysql-java", ver: "5.1.49-0+deb8u1", rls: "DEB8" ) )){
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

