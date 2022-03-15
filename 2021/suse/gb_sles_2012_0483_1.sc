if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2012.0483.1" );
	script_cve_id( "CVE-2012-1126", "CVE-2012-1127", "CVE-2012-1129", "CVE-2012-1130", "CVE-2012-1131", "CVE-2012-1132", "CVE-2012-1133", "CVE-2012-1134", "CVE-2012-1135", "CVE-2012-1136", "CVE-2012-1137", "CVE-2012-1138", "CVE-2012-1139", "CVE-2012-1141", "CVE-2012-1142", "CVE-2012-1143" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:28 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-26 12:43:00 +0000 (Tue, 26 Jan 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2012:0483-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES10\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2012:0483-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2012/suse-su-20120483-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'freetype2' package(s) announced via the SUSE-SU-2012:0483-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Specially crafted font files could have caused buffer overflows in freetype. This has been fixed.

Security Issue references:

 * CVE-2012-1129
>
 * CVE-2012-1127
>
 * CVE-2012-1138
>
 * CVE-2012-1131
>
 * CVE-2012-1141
>
 * CVE-2012-1132
>
 * CVE-2012-1139
>
 * CVE-2012-1137
>
 * CVE-2012-1126
>
 * CVE-2012-1142
>
 * CVE-2012-1130
>
 * CVE-2012-1136
>
 * CVE-2012-1143
>
 * CVE-2012-1133
>
 * CVE-2012-1135
>
 * CVE-2012-1134
>" );
	script_tag( name: "affected", value: "'freetype2' package(s) on SUSE Linux Enterprise Desktop 10 SP4, SUSE Linux Enterprise Server 10 SP4." );
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
if(release == "SLES10.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "freetype2", rpm: "freetype2~2.1.10~18.29.6", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freetype2-32bit", rpm: "freetype2-32bit~2.1.10~18.29.6", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freetype2-64bit", rpm: "freetype2-64bit~2.1.10~18.29.6", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freetype2-devel", rpm: "freetype2-devel~2.1.10~18.29.6", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freetype2-devel-32bit", rpm: "freetype2-devel-32bit~2.1.10~18.29.6", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freetype2-devel-64bit", rpm: "freetype2-devel-64bit~2.1.10~18.29.6", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freetype2-x86", rpm: "freetype2-x86~2.1.10~18.29.6", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ft2demos", rpm: "ft2demos~2.1.10~19.29.2", rls: "SLES10.0SP4" ) )){
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

