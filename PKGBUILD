# Maintainer: Army <uli armbruster who uses the google mail service>

pkgname=ldm-git
_pkgname=ldm
pkgver=20120108
pkgrel=1
pkgdesc="A lightweight device mounter"
arch=('i686' 'x86_64')
url="https://github.com/LemonBoy/ldm"
license=(MIT)
depends=('udev')
makedepends=('git')
provides=(${_pkgname})
conflicts=(${_pkgname})

_gitroot="https://github.com/LemonBoy/ldm.git"
_gitname="${_pkgname}"

build() {
	cd "$srcdir"
	msg "Connecting to GIT server...."
	
	if [ -d ${_gitname} ] ; then
		cd ${_gitname} && git pull origin
		msg "The local files are updated."
	else
		git clone ${_gitroot} ${_gitname}
	fi
	msg "GIT checkout done or server timeout"
	msg "Starting make..."

	rm -rf "${srcdir}/${_gitname}-build"
	cp -a "${srcdir}/${_gitname}" "${srcdir}/${_gitname}-build"
	cd "${srcdir}/${_gitname}-build"

    echo "#define CONFIG_USER_UID " $(shell id -u $(who | awk '{print$1}')) > config.h  
    echo "#define CONFIG_USER_GID " $(shell id -g $(who | awk '{print$1}')) >> config.h

	make
}

package() {
	install -Dm755 "${srcdir}/${_gitname}-build/${_pkgname}.daemon" "${pkgdir}/etc/rc.d/${_pkgname}"
	install -Dm755 "${srcdir}/${_gitname}-build/${_pkgname}" "${pkgdir}/usr/bin/${_pkgname}"
	install -Dm644 "${srcdir}/${_gitname}-build/LICENSE" "${pkgdir}/usr/share/licenses/${pkgname}/LICENSE"
}
