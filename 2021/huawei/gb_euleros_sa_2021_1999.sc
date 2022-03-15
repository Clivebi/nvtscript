if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2021.1999" );
	script_cve_id( "CVE-2021-27218", "CVE-2021-27219", "CVE-2021-28153" );
	script_tag( name: "creation_date", value: "2021-07-01 07:37:51 +0000 (Thu, 01 Jul 2021)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-07 10:15:00 +0000 (Wed, 07 Jul 2021)" );
	script_name( "Huawei EulerOS: Security Advisory for glib2 (EulerOS-SA-2021-1999)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRTARM64\\-3\\.0\\.6\\.0" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2021-1999" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1999" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'glib2' package(s) announced via the EulerOS-SA-2021-1999 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "An issue was discovered in GNOME GLib before 2.66.8. When g_file_replace() is used with G_FILE_CREATE_REPLACE_DESTINATION to replace a path that is a dangling symlink, it incorrectly also creates the target of the symlink as an empty file, which could conceivably have security relevance if the symlink is attacker-controlled. (If the path is a symlink to a file that already exists, then the contents of that file correctly remain unchanged.)(CVE-2021-28153)

An issue was discovered in GNOME GLib before 2.66.7 and 2.67.x before 2.67.4. If g_byte_array_new_take() was called with a buffer of 4GB or more on a 64-bit platform, the length would be truncated modulo 2**32, causing unintended length truncation.(CVE-2021-27218)

An issue was discovered in GNOME GLib before 2.66.6 and 2.67.x before 2.67.3. The function g_bytes_new has an integer overflow on 64-bit platforms due to an implicit cast from 64 bits to 32 bits. The overflow could potentially lead to memory corruption.(CVE-2021-27219)" );
	script_tag( name: "affected", value: "'glib2' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.6.0." );
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
if(release == "EULEROSVIRTARM64-3.0.6.0"){
	if(!isnull( res = isrpmvuln( pkg: "glib2", rpm: "glib2~2.58.1~1.h9.eulerosv2r8", rls: "EULEROSVIRTARM64-3.0.6.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glib2-devel", rpm: "glib2-devel~2.58.1~1.h9.eulerosv2r8", rls: "EULEROSVIRTARM64-3.0.6.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glib2-fam", rpm: "glib2-fam~2.58.1~1.h9.eulerosv2r8", rls: "EULEROSVIRTARM64-3.0.6.0" ) )){
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

