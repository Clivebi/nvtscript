if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.850824" );
	script_version( "2020-01-31T07:58:03+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 07:58:03 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2015-10-13 18:35:01 +0530 (Tue, 13 Oct 2015)" );
	script_cve_id( "CVE-2014-9328", "CVE-2015-1461", "CVE-2015-1462", "CVE-2015-1463" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "SUSE: Security Advisory for clamav (SUSE-SU-2015:0298-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'clamav'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "clamav was updated to version 0.98.6 to fix four security issues.

  These security issues have been fixed:

  * CVE-2015-1462: ClamAV allowed remote attackers to have unspecified
  impact via a crafted upx packer file, related to a heap out of
  bounds condition (bnc#916214).

  * CVE-2015-1463: ClamAV allowed remote attackers to cause a denial of
  service (crash) via a crafted petite packer file, related to an
  incorrect compiler optimization (bnc#916215).

  * CVE-2014-9328: ClamAV allowed remote attackers to have unspecified
  impact via a crafted upack packer file, related to a heap out of
  bounds condition (bnc#915512).

  * CVE-2015-1461: ClamAV allowed remote attackers to have unspecified
  impact via a crafted (1) Yoda's crypter or (2) mew packer file,
  related to a heap out of bounds condition (bnc#916217)." );
	script_tag( name: "affected", value: "clamav on SUSE Linux Enterprise Server 11 SP3" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "SUSE-SU", value: "2015:0298-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=SLES11\\.0SP3" );
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
if(release == "SLES11.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "clamav", rpm: "clamav~0.98.6~0.6.1", rls: "SLES11.0SP3" ) )){
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
