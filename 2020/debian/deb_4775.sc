if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704775" );
	script_version( "2021-07-26T02:01:39+0000" );
	script_cve_id( "CVE-2020-25032" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-07-26 02:01:39 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-21 12:15:00 +0000 (Wed, 21 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-10-22 03:00:15 +0000 (Thu, 22 Oct 2020)" );
	script_name( "Debian: Security Advisory for python-flask-cors (DSA-4775-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2020/dsa-4775.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4775-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-flask-cors'
  package(s) announced via the DSA-4775-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A directory traversal vulnerability was discovered in python-flask-cors,
a Flask extension for handling Cross Origin Resource Sharing (CORS),
allowing to access private resources." );
	script_tag( name: "affected", value: "'python-flask-cors' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), this problem has been fixed in
version 3.0.7-1+deb10u1.

We recommend that you upgrade your python-flask-cors packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "python3-flask-cors", ver: "3.0.7-1+deb10u1", rls: "DEB10" ) )){
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
