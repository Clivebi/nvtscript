if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843174" );
	script_version( "2021-09-16T08:01:42+0000" );
	script_tag( name: "last_modification", value: "2021-09-16 08:01:42 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-05-18 06:50:06 +0200 (Thu, 18 May 2017)" );
	script_cve_id( "CVE-2016-0634", "CVE-2016-7543", "CVE-2016-9401", "CVE-2017-5932" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for bash USN-3294-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'bash'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Bernd Dietzel discovered that Bash
  incorrectly expanded the hostname when displaying the prompt. If a remote
  attacker were able to modify a hostname, this flaw could be exploited to execute
  arbitrary code. This issue only affected Ubuntu 14.04 LTS, Ubuntu 16.04 LTS and
  Ubuntu 16.10. (CVE-2016-0634) It was discovered that Bash incorrectly handled
  the SHELLOPTS and PS4 environment variables. A local attacker could use this
  issue to execute arbitrary code with root privileges. This issue only affected
  Ubuntu 14.04 LTS, Ubuntu 16.04 LTS and Ubuntu 16.10. (CVE-2016-7543) It was
  discovered that Bash incorrectly handled the popd command. A remote attacker
  could possibly use this issue to bypass restricted shells. (CVE-2016-9401) It
  was discovered that Bash incorrectly handled path autocompletion. A local
  attacker could possibly use this issue to execute arbitrary code. This issue
  only affected Ubuntu 17.04. (CVE-2017-5932)" );
	script_tag( name: "affected", value: "bash on Ubuntu 17.04,
  Ubuntu 16.10,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3294-1" );
	script_xref( name: "URL", value: "https://www.ubuntu.com/usn/usn-3294-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|17\\.04|16\\.10|16\\.04 LTS)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "bash", ver: "4.3-7ubuntu1.7", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU17.04"){
	if(( res = isdpkgvuln( pkg: "bash", ver: "4.4-2ubuntu1.1", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.10"){
	if(( res = isdpkgvuln( pkg: "bash", ver: "4.3-15ubuntu1.1", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "bash", ver: "4.3-14ubuntu1.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

