if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844356" );
	script_version( "2021-07-09T11:00:55+0000" );
	script_cve_id( "CVE-2020-8794", "CVE-2020-8793" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-07-09 11:00:55 +0000 (Fri, 09 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-04 18:15:00 +0000 (Tue, 04 May 2021)" );
	script_tag( name: "creation_date", value: "2020-03-03 04:01:05 +0000 (Tue, 03 Mar 2020)" );
	script_name( "Ubuntu: Security Advisory for opensmtpd (USN-4294-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU19\\.10|UBUNTU18\\.04 LTS)" );
	script_xref( name: "USN", value: "4294-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-March/005348.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'opensmtpd'
  package(s) announced via the USN-4294-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that OpenSMTPD mishandled certain input. A remote,
unauthenticated attacker could use this vulnerability to execute arbitrary
shell commands as any non-root user. (CVE-2020-8794)

It was discovered that OpenSMTPD did not properly handle hardlinks under
certain conditions. An unprivileged local attacker could read the first
line of any file on the filesystem. (CVE-2020-8793)" );
	script_tag( name: "affected", value: "'opensmtpd' package(s) on Ubuntu 19.10, Ubuntu 18.04 LTS." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "UBUNTU19.10"){
	if(!isnull( res = isdpkgvuln( pkg: "opensmtpd", ver: "6.0.3p1-6ubuntu0.2", rls: "UBUNTU19.10" ) )){
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
}
if(release == "UBUNTU18.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "opensmtpd", ver: "6.0.3p1-1ubuntu0.2", rls: "UBUNTU18.04 LTS" ) )){
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
}
exit( 0 );

