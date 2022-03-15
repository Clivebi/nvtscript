if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844560" );
	script_version( "2021-07-09T11:00:55+0000" );
	script_cve_id( "CVE-2020-12689", "CVE-2020-12691", "CVE-2020-12690", "CVE-2020-12692" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-09 11:00:55 +0000 (Fri, 09 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-02 16:15:00 +0000 (Wed, 02 Sep 2020)" );
	script_tag( name: "creation_date", value: "2020-09-02 11:51:28 +0530 (Wed, 02 Sep 2020)" );
	script_name( "Ubuntu: Security Advisory for keystone (USN-4480-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU18\\.04 LTS" );
	script_xref( name: "USN", value: "4480-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-September/005585.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'keystone'
  package(s) announced via the USN-4480-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that OpenStack Keystone incorrectly handled EC2
credentials. An authenticated attacker with a limited scope could possibly
create EC2 credentials with escalated permissions. (CVE-2020-12689,
CVE-2020-12691)

It was discovered that OpenStack Keystone incorrectly handled the list of
roles provided with OAuth1 access tokens. An authenticated user could
possibly end up with more role assignments than intended. (CVE-2020-12690)

It was discovered that OpenStack Keystone incorrectly handled EC2 signature
TTL checks. A remote attacker could possibly use this issue to reuse
Authorization headers. (CVE-2020-12692)" );
	script_tag( name: "affected", value: "'keystone' package(s) on Ubuntu 18.04 LTS." );
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
if(release == "UBUNTU18.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "keystone", ver: "2:13.0.4-0ubuntu1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "python-keystone", ver: "2:13.0.4-0ubuntu1", rls: "UBUNTU18.04 LTS" ) )){
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

