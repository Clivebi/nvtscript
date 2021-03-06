if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704425" );
	script_version( "2021-09-02T14:01:33+0000" );
	script_cve_id( "CVE-2019-5953" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-02 14:01:33 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-04-07 02:00:06 +0000 (Sun, 07 Apr 2019)" );
	script_name( "Debian Security Advisory DSA 4425-1 (wget - security update)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4425.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4425-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'wget'
  package(s) announced via the DSA-4425-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Kusano Kazuhiko discovered a buffer overflow vulnerability in the
handling of Internationalized Resource Identifiers (IRI) in wget, a
network utility to retrieve files from the web, which could result in
the execution of arbitrary code or denial of service when recursively
downloading from an untrusted server." );
	script_tag( name: "affected", value: "'wget' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (stretch), this problem has been fixed in
version 1.18-5+deb9u3.

We recommend that you upgrade your wget packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "wget", ver: "1.18-5+deb9u3", rls: "DEB9" ) )){
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

