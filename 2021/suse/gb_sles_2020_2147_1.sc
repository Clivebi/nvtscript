if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.2147.1" );
	script_cve_id( "CVE-2020-15652", "CVE-2020-15653", "CVE-2020-15654", "CVE-2020-15655", "CVE-2020-15656", "CVE-2020-15657", "CVE-2020-15658", "CVE-2020-15659", "CVE-2020-6463", "CVE-2020-6514" );
	script_tag( name: "creation_date", value: "2021-06-09 14:56:56 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-18 14:15:00 +0000 (Tue, 18 Aug 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:2147-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:2147-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-20202147-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'MozillaFirefox' package(s) announced via the SUSE-SU-2020:2147-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for MozillaFirefox fixes the following issues:

This update for MozillaFirefox and pipewire fixes the following issues:

MozillaFirefox Extended Support Release 78.1.0 ESR

Fixed: Various stability, functionality, and security fixes (bsc#1174538)

CVE-2020-15652: Potential leak of redirect targets when loading scripts
 in a worker

CVE-2020-6514: WebRTC data channel leaks internal address to peer

CVE-2020-15655: Extension APIs could be used to bypass Same-Origin Policy

CVE-2020-15653: Bypassing iframe sandbox when allowing popups

CVE-2020-6463: Use-after-free in ANGLE
 gl::Texture::onUnbindAsSamplerTexture

CVE-2020-15656: Type confusion for special arguments in IonMonkey

CVE-2020-15658: Overriding file type when saving to disk

CVE-2020-15657: DLL hijacking due to incorrect loading path

CVE-2020-15654: Custom cursor can overlay user interface

CVE-2020-15659: Memory safety bugs fixed in Firefox 79 and Firefox ESR
 78.1

pipewire was updated to version 0.3.6 (bsc#1171433, jsc#ECO-2308):

Extensive memory leak fixing and stress testing was done. A big leak in
 screen sharing with DMA-BUF was fixed.

Compile fixes

Stability improvements in jack and pulseaudio layers.

Added the old portal module to make the Camera portal work again. This
 will be moved to the session manager in future versions.

Improvements to the GStreamer source and sink shutdown.

Fix compatibility with v2 clients again when negotiating buffers." );
	script_tag( name: "affected", value: "'MozillaFirefox' package(s) on SUSE Linux Enterprise Module for Desktop Applications 15-SP2." );
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
if(release == "SLES15.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox", rpm: "MozillaFirefox~78.1.0~8.3.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-branding-SLE", rpm: "MozillaFirefox-branding-SLE~78~9.2.4", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-debuginfo", rpm: "MozillaFirefox-debuginfo~78.1.0~8.3.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-debugsource", rpm: "MozillaFirefox-debugsource~78.1.0~8.3.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-devel", rpm: "MozillaFirefox-devel~78.1.0~8.3.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-translations-common", rpm: "MozillaFirefox-translations-common~78.1.0~8.3.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-translations-other", rpm: "MozillaFirefox-translations-other~78.1.0~8.3.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpipewire-0_3-0", rpm: "libpipewire-0_3-0~0.3.6~3.3.2", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpipewire-0_3-0-debuginfo", rpm: "libpipewire-0_3-0-debuginfo~0.3.6~3.3.2", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pipewire", rpm: "pipewire~0.3.6~3.3.2", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pipewire-debuginfo", rpm: "pipewire-debuginfo~0.3.6~3.3.2", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pipewire-debugsource", rpm: "pipewire-debugsource~0.3.6~3.3.2", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pipewire-modules", rpm: "pipewire-modules~0.3.6~3.3.2", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pipewire-modules-debuginfo", rpm: "pipewire-modules-debuginfo~0.3.6~3.3.2", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pipewire-spa-plugins-0_2", rpm: "pipewire-spa-plugins-0_2~0.3.6~3.3.2", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pipewire-spa-plugins-0_2-debuginfo", rpm: "pipewire-spa-plugins-0_2-debuginfo~0.3.6~3.3.2", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pipewire-spa-tools", rpm: "pipewire-spa-tools~0.3.6~3.3.2", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pipewire-spa-tools-debuginfo", rpm: "pipewire-spa-tools-debuginfo~0.3.6~3.3.2", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pipewire-tools", rpm: "pipewire-tools~0.3.6~3.3.2", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pipewire-tools-debuginfo", rpm: "pipewire-tools-debuginfo~0.3.6~3.3.2", rls: "SLES15.0SP2" ) )){
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

