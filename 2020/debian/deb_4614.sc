if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704614" );
	script_version( "2021-07-23T11:01:09+0000" );
	script_cve_id( "CVE-2019-18634" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-23 11:01:09 +0000 (Fri, 23 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-02-07 17:15:00 +0000 (Fri, 07 Feb 2020)" );
	script_tag( name: "creation_date", value: "2020-02-02 04:00:12 +0000 (Sun, 02 Feb 2020)" );
	script_name( "Debian: Security Advisory for sudo (DSA-4614-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2020/dsa-4614.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4614-1" );
	script_xref( name: "URL", value: "https://www.sudo.ws/alerts/pwfeedback.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'sudo'
  package(s) announced via the DSA-4614-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Joe Vennix discovered a stack-based buffer overflow vulnerability in
sudo, a program designed to provide limited super user privileges to
specific users, triggerable when configured with the pwfeedback
option enabled. An unprivileged user can take advantage of this flaw to obtain
full root privileges.

Details can be found in the referenced upstream advisory." );
	script_tag( name: "affected", value: "'sudo' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the oldstable distribution (stretch), this problem has been fixed
in version 1.8.19p1-2.1+deb9u2.

For the stable distribution (buster), exploitation of the bug is
prevented due to a change in EOF handling introduced in 1.8.26.

We recommend that you upgrade your sudo packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "sudo", ver: "1.8.19p1-2.1+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "sudo-ldap", ver: "1.8.19p1-2.1+deb9u2", rls: "DEB9" ) )){
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

