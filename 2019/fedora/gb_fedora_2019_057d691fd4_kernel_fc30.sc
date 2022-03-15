if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876925" );
	script_version( "2021-09-01T12:01:34+0000" );
	script_cve_id( "CVE-2019-17052", "CVE-2019-17053", "CVE-2019-17054", "CVE-2019-17055", "CVE-2019-17056", "CVE-2019-14821", "CVE-2019-15504", "CVE-2019-15505", "CVE-2019-15538", "CVE-2019-14814", "CVE-2019-14815", "CVE-2019-14816", "CVE-2019-10207", "CVE-2019-13631", "CVE-2019-12817", "CVE-2019-11477", "CVE-2019-11479", "CVE-2019-11478", "CVE-2019-10126", "CVE-2019-12614", "CVE-2019-12456", "CVE-2019-12455", "CVE-2019-12454", "CVE-2019-12378", "CVE-2019-3846", "CVE-2019-12380", "CVE-2019-12381", "CVE-2019-12382", "CVE-2019-12379", "CVE-2018-12126", "CVE-2018-12127", "CVE-2018-12130", "CVE-2019-11091", "CVE-2019-11884", "CVE-2019-3900", "CVE-2019-16746" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-01 12:01:34 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-09-04 05:15:00 +0000 (Wed, 04 Sep 2019)" );
	script_tag( name: "creation_date", value: "2019-10-19 02:34:51 +0000 (Sat, 19 Oct 2019)" );
	script_name( "Fedora Update for kernel FEDORA-2019-057d691fd4" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC30" );
	script_xref( name: "FEDORA", value: "2019-057d691fd4" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/36DYF7IFYJ54ACYU7WV4ZGCJ577DSPQL" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'kernel'
  package(s) announced via the FEDORA-2019-057d691fd4 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The kernel meta package" );
	script_tag( name: "affected", value: "'kernel' package(s) on Fedora 30." );
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
	if(!isnull( res = isrpmvuln( pkg: "kernel", rpm: "kernel~5.3.6~200.fc30", rls: "FC30" ) )){
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

