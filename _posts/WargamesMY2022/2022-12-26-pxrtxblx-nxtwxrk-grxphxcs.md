---
title : "Pxrtxblx Nxtwxrk Grxphxcs [Misc]"
categories: WargamesMY2022
---

Patch corrupted PNG file to recover the image.

# Challenge Description

Cxn yxx rxcxvxr xt?

[chal.png]({{ site.url }}/files/wgmy2022/chal.png){: .btn .btn--info}

# Solution

First, we must understand the PNG file structure. A PNG file consists of multiple sections, mainly IDAT, which contains the data of the image. All the sections must be valid according to the specification.

I used an [online tool](https://www.nayuki.io/page/png-file-chunk-inspector) to make my life easier.

We immediately see that the file signature is wrong. More precisely, the first few bytes (known as the magic bytes) are not that of a PNG file's. We can quickly fix that with a hex editor.

<div style="display: flex; justify-content: center; margin: 0 0 60px;">
<video width="640" height="360" muted autoplay loop playsinline>
  <source src="/assets/video/wgmy2022/pngfix.mov" type="video/mp4">
  Your browser does not support video playback.
</video>
</div>

Then, we reupload the fixed image onto the tool from earlier.

{% include image.html url="/assets/images/wgmy2022/check1.png" description="CRC error detected here" %}
{% include image.html url="/assets/images/wgmy2022/check2.png" description="Unknown chunk of data after IEND" %}

I replaced the CRC with what's expected, assuming the data is correct, and removed the unknown chunk of data.

However, the image was empty. I fiddled around with `pngcheck` and found out it's something wrong with the IDAT section, because a zlib error -5 (buffering error) was thrown.

I had no idea how to fix so I just used an [online tool](https://compress-or-die.com/repair) again. And that worked, giving us the image with the flag.

{% include image.html url="/assets/images/wgmy2022/pngflag.png" description="Flag found here in the fixed image" %}

Flag: `wgmy{e6fb725a5b2e25429442dbd568ce058e}`

