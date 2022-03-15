if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2020.1387" );
	script_cve_id( "CVE-2019-12450", "CVE-2019-13012" );
	script_tag( name: "creation_date", value: "2020-04-16 05:46:05 +0000 (Thu, 16 Apr 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_name( "Huawei EulerOS: Security Advisory for glib2 (EulerOS-SA-2020-1387)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP3" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2020-1387" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1387" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'glib2' package(s) announced via the EulerOS-SA-2020-1387 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "file_copy_fallback in gio/gfile.c in GNOME GLib 2.15.0 through 2.61.1 does not properly restrict file permissions while a copy operation is in progress. Instead, default permissions are used.(CVE-2019-12450)

The keyfile settings backend in GNOME GLib (aka glib2.0) before 2.60.0 creates directories using g_file_make_directory_with_parents (kfsb->dir, NULL, NULL) and files using g_file_replace_contents (kfsb->file, contents, length, NULL, FALSE, G_FILE_CREATE_REPLACE_DESTINATION, NULL, NULL, NULL). Consequently, it does not properly restrict directory (and file) permissions. Instead, for directories, 0777 permissions are used, for files, default file permissions are used. This is similar to CVE-2019-12450.(CVE-2019-13012)" );
	script_tag( name: "affected", value: "'glib2' package(s) on Huawei EulerOS V2.0SP3." );
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
if(release == "EULEROS-2.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "glib2", rpm: "glib2~2.50.3~3.h4", rls: "EULEROS-2.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glib2-devel", rpm: "glib2-devel~2.50.3~3.h4", rls: "EULEROS-2.0SP3" ) )){
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

