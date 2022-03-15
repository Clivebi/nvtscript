if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877013" );
	script_version( "2021-09-01T14:01:32+0000" );
	script_cve_id( "CVE-2019-10218", "CVE-2019-14833", "CVE-2019-14847", "CVE-2019-10197", "CVE-2019-12435", "CVE-2018-16860", "CVE-2019-3870", "CVE-2019-3880", "CVE-2018-14629", "CVE-2018-16841", "CVE-2018-16851", "CVE-2018-16852", "CVE-2018-16853", "CVE-2018-16857" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 14:01:32 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-18 15:05:00 +0000 (Tue, 18 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-11-17 03:31:56 +0000 (Sun, 17 Nov 2019)" );
	script_name( "Fedora Update for samba FEDORA-2019-703e299870" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC29" );
	script_xref( name: "FEDORA", value: "2019-703e299870" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/OKPYHDFI7HRELVXBE5J4MTGSI35AKFBI" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'samba'
  package(s) announced via the FEDORA-2019-703e299870 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Samba is the standard Windows interoperability suite of programs for Linux and
Unix." );
	script_tag( name: "affected", value: "'samba' package(s) on Fedora 29." );
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
if(release == "FC29"){
	if(!isnull( res = isrpmvuln( pkg: "samba", rpm: "samba~4.9.15~0.fc29", rls: "FC29" ) )){
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

