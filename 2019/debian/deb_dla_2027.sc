if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892027" );
	script_version( "2021-09-02T14:01:33+0000" );
	script_cve_id( "CVE-2017-17742", "CVE-2019-16201", "CVE-2019-16254", "CVE-2019-16255" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-09-02 14:01:33 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-16 15:15:00 +0000 (Sun, 16 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-12-11 03:00:26 +0000 (Wed, 11 Dec 2019)" );
	script_name( "Debian LTS: Security Advisory for jruby (DLA-2027-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/12/msg00009.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2027-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'jruby'
  package(s) announced via the DLA-2027-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several security vulnerabilities were found in Ruby that also affected
Debian's JRuby package, a pure-Java implementation of Ruby. Attackers
were able to call arbitrary Ruby methods, cause a denial-of-service or
inject input into HTTP response headers when using the WEBrick module." );
	script_tag( name: "affected", value: "'jruby' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
1.5.6-9+deb8u2.

We recommend that you upgrade your jruby packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "jruby", ver: "1.5.6-9+deb8u2", rls: "DEB8" ) )){
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

