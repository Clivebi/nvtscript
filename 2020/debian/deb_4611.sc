if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704611" );
	script_version( "2021-07-26T02:01:39+0000" );
	script_cve_id( "CVE-2020-7247" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-07-26 02:01:39 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-06 16:15:00 +0000 (Tue, 06 Apr 2021)" );
	script_tag( name: "creation_date", value: "2020-01-31 04:00:05 +0000 (Fri, 31 Jan 2020)" );
	script_name( "Debian: Security Advisory for opensmtpd (DSA-4611-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(10|9)" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2020/dsa-4611.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4611-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'opensmtpd'
  package(s) announced via the DSA-4611-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Qualys discovered that the OpenSMTPD SMTP server performed insufficient
validation of email addresses which could result in the execution of
arbitrary commands as root. In addition this update fixes a denial of
service by triggering an opportunistic TLS downgrade." );
	script_tag( name: "affected", value: "'opensmtpd' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the oldstable distribution (stretch), these problems have been fixed
in version 6.0.2p1-2+deb9u2.

For the stable distribution (buster), these problems have been fixed in
version 6.0.3p1-5+deb10u3. This update also includes non-security
bugfixes which were already lined up for the Buster 10.3 point release.

We recommend that you upgrade your opensmtpd packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "opensmtpd", ver: "6.0.3p1-5+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "opensmtpd", ver: "6.0.2p1-2+deb9u2", rls: "DEB9" ) )){
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

