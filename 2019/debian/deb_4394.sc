if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704394" );
	script_version( "2021-09-03T08:01:30+0000" );
	script_cve_id( "CVE-2018-20174", "CVE-2018-20175", "CVE-2018-20176", "CVE-2018-20177", "CVE-2018-20178", "CVE-2018-20179", "CVE-2018-20180", "CVE-2018-20181", "CVE-2018-20182", "CVE-2018-8791", "CVE-2018-8792", "CVE-2018-8793", "CVE-2018-8794", "CVE-2018-8795", "CVE-2018-8796", "CVE-2018-8797", "CVE-2018-8798", "CVE-2018-8799", "CVE-2018-8800" );
	script_name( "Debian Security Advisory DSA 4394-1 (rdesktop - security update)" );
	script_tag( name: "last_modification", value: "2021-09-03 08:01:30 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-02-18 00:00:00 +0100 (Mon, 18 Feb 2019)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4394.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "rdesktop on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), these problems have been fixed in
version 1.8.4-1~deb9u1.

We recommend that you upgrade your rdesktop packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/rdesktop" );
	script_tag( name: "summary", value: "Multiple security issues were found in the rdesktop RDP client, which
could result in denial of service, information disclosure and the
execution of arbitrary code." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "rdesktop", ver: "1.8.4-1~deb9u1", rls: "DEB9" ) )){
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

