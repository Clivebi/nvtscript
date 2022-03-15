if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844064" );
	script_version( "2021-08-31T08:01:19+0000" );
	script_cve_id( "CVE-2016-10321", "CVE-2016-3952", "CVE-2016-3953", "CVE-2016-3954", "CVE-2016-3957" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-31 08:01:19 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-21 22:15:00 +0000 (Fri, 21 Jun 2019)" );
	script_tag( name: "creation_date", value: "2019-06-22 02:00:31 +0000 (Sat, 22 Jun 2019)" );
	script_name( "Ubuntu Update for web2py USN-4030-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU16\\.04 LTS" );
	script_xref( name: "USN", value: "4030-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2019-June/004975.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'web2py'
  package(s) announced via the USN-4030-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that web2py does not properly check denied hosts before 
verifying passwords. An attacker could possibly use this issue to perform
brute-force attacks. (CVE-2016-10321)

It was discovered that web2py allows remote attackers to obtain
environment variable values. An attacker could possibly use this issue to
gain administrative access. (CVE-2016-3952)

It was discovered that web2py uses a hardcoded encryption key. An
attacker could possibly use this issue to execute arbitrary code.
(CVE-2016-3953, CVE-2016-3954, CVE-2016-3957)" );
	script_tag( name: "affected", value: "'web2py' package(s) on Ubuntu 16.04 LTS." );
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
if(release == "UBUNTU16.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "python-gluon", ver: "2.12.3-1ubuntu0.1", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "python-web2py", ver: "2.12.3-1ubuntu0.1", rls: "UBUNTU16.04 LTS" ) )){
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

