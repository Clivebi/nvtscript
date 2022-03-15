if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.872516" );
	script_version( "2021-09-08T11:01:32+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 11:01:32 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-03-22 05:53:52 +0100 (Wed, 22 Mar 2017)" );
	script_cve_id( "CVE-2017-5525", "CVE-2017-5526", "CVE-2016-10155", "CVE-2017-5552", "CVE-2017-5667", "CVE-2017-5857", "CVE-2017-5856", "CVE-2017-5898", "CVE-2017-5987", "CVE-2017-6505", "CVE-2017-2615", "CVE-2017-2620" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-09-07 10:29:00 +0000 (Fri, 07 Sep 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for qemu FEDORA-2017-62ac1230f7" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'qemu'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "qemu on Fedora 24" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2017-62ac1230f7" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/X3M6HH35GUTRSIKPUWQYKAFUOT25GJXE" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC24" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC24"){
	if(( res = isrpmvuln( pkg: "qemu", rpm: "qemu~2.6.2~7.fc24", rls: "FC24" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

