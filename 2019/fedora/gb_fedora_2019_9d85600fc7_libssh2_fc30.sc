if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876630" );
	script_version( "2021-09-01T13:01:35+0000" );
	script_cve_id( "CVE-2019-3855", "CVE-2019-13115" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-01 13:01:35 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-15 13:42:00 +0000 (Thu, 15 Oct 2020)" );
	script_tag( name: "creation_date", value: "2019-08-04 02:15:59 +0000 (Sun, 04 Aug 2019)" );
	script_name( "Fedora Update for libssh2 FEDORA-2019-9d85600fc7" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC30" );
	script_xref( name: "FEDORA", value: "2019-9d85600fc7" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/6LUNHPW64IGCASZ4JQ2J5KDXNZN53DWW" );
	script_tag( name: "summary", value: "The remote host is missing an update for the
  'libssh2' package(s) announced via the FEDORA-2019-9d85600fc7 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is
  present on the target host." );
	script_tag( name: "insight", value: "libssh2 is a library implementing the SSH2
  protocol as defined by Internet Drafts: SECSH-TRANS(22), SECSH-USERAUTH(25),
  SECSH-CONNECTION(23), SECSH-ARCH(20), SECSH-FILEXFER(06)*, SECSH-DHGEX(04),
  and SECSH-NUMBERS(10)." );
	script_tag( name: "affected", value: "'libssh2' package(s) on Fedora 30." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "FC30"){
	if(!isnull( res = isrpmvuln( pkg: "libssh2", rpm: "libssh2~1.9.0~1.fc30", rls: "FC30" ) )){
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
