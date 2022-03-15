if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704861" );
	script_version( "2021-08-25T09:01:10+0000" );
	script_cve_id( "CVE-2021-26937" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-25 09:01:10 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-26 10:15:00 +0000 (Wed, 26 May 2021)" );
	script_tag( name: "creation_date", value: "2021-02-23 04:00:05 +0000 (Tue, 23 Feb 2021)" );
	script_name( "Debian: Security Advisory for screen (DSA-4861-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2021/dsa-4861.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4861-1" );
	script_xref( name: "Advisory-ID", value: "DSA-4861-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'screen'
  package(s) announced via the DSA-4861-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Felix Weinmann reported a flaw in the handling of combining characters
in screen, a terminal multiplexer with VT100/ANSI terminal emulation,
which can result in denial of service, or potentially the execution of
arbitrary code via a specially crafted UTF-8 character sequence." );
	script_tag( name: "affected", value: "'screen' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), this problem has been fixed in
version 4.6.2-3+deb10u1.

We recommend that you upgrade your screen packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "screen", ver: "4.6.2-3+deb10u1", rls: "DEB10" ) )){
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

