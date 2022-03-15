if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808485" );
	script_version( "2021-09-17T12:01:50+0000" );
	script_tag( name: "last_modification", value: "2021-09-17 12:01:50 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-06-27 05:45:17 +0200 (Mon, 27 Jun 2016)" );
	script_cve_id( "CVE-2016-4002", "CVE-2016-4952", "CVE-2016-4964", "CVE-2016-5106", "CVE-2016-5105", "CVE-2016-5107", "CVE-2016-4454", "CVE-2016-4453", "CVE-2016-5126", "CVE-2016-5238", "CVE-2016-5338", "CVE-2016-5337" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-14 19:54:00 +0000 (Mon, 14 Dec 2020)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for qemu FEDORA-2016-a80eab65ba" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'qemu'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "qemu on Fedora 24" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2016-a80eab65ba" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/S3BTAPSNRRE3KNPXA23MAHEY7NOE424J" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
	if(( res = isrpmvuln( pkg: "qemu", rpm: "qemu~2.6.0~4.fc24", rls: "FC24" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

