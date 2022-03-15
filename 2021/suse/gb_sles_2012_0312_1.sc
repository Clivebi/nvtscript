if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2012.0312.1" );
	script_cve_id( "CVE-2010-4818", "CVE-2010-4819" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:28 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2012-09-06 13:40:00 +0000 (Thu, 06 Sep 2012)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2012:0312-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES10\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2012:0312-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2012/suse-su-20120312-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xorg-x11' package(s) announced via the SUSE-SU-2012:0312-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update of xorg-x11 fixes issues that could allow attackers using GLX opcodes to read access to arbitrary memory locations (CVE-2010-4818). Additionally, a crash due to missing bounds checks in the Glyph Render protocol have been fixed (CVE-2010-4819).

Access to the X server by the attacker was required to make this work.

Security Issue references:

 * CVE-2010-4819
>
 * CVE-2010-4818
>" );
	script_tag( name: "affected", value: "'xorg-x11' package(s) on SLE SDK 10 SP4, SUSE Linux Enterprise Desktop 10 SP4, SUSE Linux Enterprise Server 10 SP4." );
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
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11", rpm: "xorg-x11~6.9.0~50.78.5", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-Xnest", rpm: "xorg-x11-Xnest~6.9.0~50.78.5", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-Xvfb", rpm: "xorg-x11-Xvfb~6.9.0~50.78.5", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-Xvnc", rpm: "xorg-x11-Xvnc~6.9.0~50.78.5", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-devel-32bit", rpm: "xorg-x11-devel-32bit~6.9.0~50.78.5", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-devel", rpm: "xorg-x11-devel~6.9.0~50.78.5", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-devel-64bit", rpm: "xorg-x11-devel-64bit~6.9.0~50.78.5", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-doc", rpm: "xorg-x11-doc~6.9.0~50.78.5", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-fonts-100dpi", rpm: "xorg-x11-fonts-100dpi~6.9.0~50.78.5", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-fonts-75dpi", rpm: "xorg-x11-fonts-75dpi~6.9.0~50.78.5", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-fonts-cyrillic", rpm: "xorg-x11-fonts-cyrillic~6.9.0~50.78.5", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-fonts-scalable", rpm: "xorg-x11-fonts-scalable~6.9.0~50.78.5", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-fonts-syriac", rpm: "xorg-x11-fonts-syriac~6.9.0~50.78.5", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-libs-32bit", rpm: "xorg-x11-libs-32bit~6.9.0~50.78.5", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-libs", rpm: "xorg-x11-libs~6.9.0~50.78.5", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-libs-64bit", rpm: "xorg-x11-libs-64bit~6.9.0~50.78.5", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-libs-x86", rpm: "xorg-x11-libs-x86~6.9.0~50.78.5", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-man", rpm: "xorg-x11-man~6.9.0~50.78.5", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-sdk", rpm: "xorg-x11-sdk~6.9.0~50.78.5", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-server", rpm: "xorg-x11-server~6.9.0~50.78.5", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-server-glx", rpm: "xorg-x11-server-glx~6.9.0~50.78.5", rls: "SLES10.0SP4" ) )){
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

