if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892091" );
	script_version( "2021-07-27T11:00:54+0000" );
	script_cve_id( "CVE-2017-15095", "CVE-2017-7525", "CVE-2019-10172" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-27 11:00:54 +0000 (Tue, 27 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-22 21:41:00 +0000 (Mon, 22 Feb 2021)" );
	script_tag( name: "creation_date", value: "2020-02-01 04:00:06 +0000 (Sat, 01 Feb 2020)" );
	script_name( "Debian LTS: Security Advisory for libjackson-json-java (DLA-2091-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/01/msg00037.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2091-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libjackson-json-java'
  package(s) announced via the DLA-2091-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several vulnerabilities were fixed in libjackson-json-java.

CVE-2017-7525

Jackson Deserializer security vulnerability.

CVE-2017-15095

Block more JDK types from polymorphic deserialization.

CVE-2019-10172

XML external entity vulnerabilities." );
	script_tag( name: "affected", value: "'libjackson-json-java' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
1.9.2-3+deb8u1.

We recommend that you upgrade your libjackson-json-java packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libjackson-json-java", ver: "1.9.2-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libjackson-json-java-doc", ver: "1.9.2-3+deb8u1", rls: "DEB8" ) )){
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

