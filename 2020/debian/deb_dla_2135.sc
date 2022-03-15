if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892135" );
	script_version( "2021-07-23T11:01:09+0000" );
	script_cve_id( "CVE-2020-9546", "CVE-2020-9547", "CVE-2020-9548" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-23 11:01:09 +0000 (Fri, 23 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-22 21:44:00 +0000 (Mon, 22 Feb 2021)" );
	script_tag( name: "creation_date", value: "2020-03-06 04:00:09 +0000 (Fri, 06 Mar 2020)" );
	script_name( "Debian LTS: Security Advisory for jackson-databind (DLA-2135-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/03/msg00008.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2135-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'jackson-databind'
  package(s) announced via the DLA-2135-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The following CVEs were reported for jackson-databind source package.

CVE-2020-9546

FasterXML jackson-databind 2.x before 2.9.10.4 mishandles the
interaction between serialization gadgets and typing, related
to org.apache.hadoop.shaded.com.zaxxer.hikari.HikariConfig
(aka shaded hikari-config).

CVE-2020-9547

FasterXML jackson-databind 2.x before 2.9.10.4 mishandles the
interaction between serialization gadgets and typing, related
to com.ibatis.sqlmap.engine.transaction.jta.JtaTransactionConfig
(aka ibatis-sqlmap).

CVE-2020-9548

FasterXML jackson-databind 2.x before 2.9.10.4 mishandles the
interaction between serialization gadgets and typing, related
to br.com.anteros.dbcp.AnterosDBCPConfig (aka anteros-core)." );
	script_tag( name: "affected", value: "'jackson-databind' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
2.4.2-2+deb8u12.

We recommend that you upgrade your jackson-databind packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libjackson2-databind-java", ver: "2.4.2-2+deb8u12", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libjackson2-databind-java-doc", ver: "2.4.2-2+deb8u12", rls: "DEB8" ) )){
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

