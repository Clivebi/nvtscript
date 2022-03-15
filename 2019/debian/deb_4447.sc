if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704447" );
	script_version( "2021-09-03T08:01:30+0000" );
	script_cve_id( "CVE-2018-12126", "CVE-2018-12127", "CVE-2018-12130", "CVE-2019-11091" );
	script_tag( name: "cvss_base", value: "4.7" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-03 08:01:30 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-11 16:29:00 +0000 (Tue, 11 Jun 2019)" );
	script_tag( name: "creation_date", value: "2019-05-16 02:00:06 +0000 (Thu, 16 May 2019)" );
	script_name( "Debian Security Advisory DSA 4447-1 (intel-microcode - security update)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4447.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4447-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'intel-microcode'
  package(s) announced via the DSA-4447-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update ships updated CPU microcode for most types of Intel CPUs. It
provides mitigations for the MSBDS, MFBDS, MLPDS and MDSUM hardware
vulnerabilities.

To fully resolve these vulnerabilities it is also necessary to update
the Linux kernel packages as released in DSA 4444." );
	script_tag( name: "affected", value: "'intel-microcode' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (stretch), these problems have been fixed in
version 3.20190514.1~deb9u1.

We recommend that you upgrade your intel-microcode packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "intel-microcode", ver: "3.20190514.1~deb9u1", rls: "DEB9" ) )){
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

