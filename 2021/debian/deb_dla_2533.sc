if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892533" );
	script_version( "2021-08-25T06:00:59+0000" );
	script_cve_id( "CVE-2020-35459" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-25 06:00:59 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-02 15:00:00 +0000 (Tue, 02 Feb 2021)" );
	script_tag( name: "creation_date", value: "2021-01-26 04:00:05 +0000 (Tue, 26 Jan 2021)" );
	script_name( "Debian LTS: Security Advisory for crmsh (DLA-2533-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/01/msg00021.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2533-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2533-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'crmsh'
  package(s) announced via the DLA-2533-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that there was an in issue in the command-line tool
for the Pacemaker High Availability stack. Local attackers were able
to execute commands via shell code injection to the 'crm history'
command-line tool, potentially allowing escalation of privileges." );
	script_tag( name: "affected", value: "'crmsh' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 'Stretch', this problem has been fixed in version
2.3.2-4+deb9u1.

We recommend that you upgrade your crmsh packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "crmsh", ver: "2.3.2-4+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "crmsh-doc", ver: "2.3.2-4+deb9u1", rls: "DEB9" ) )){
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

