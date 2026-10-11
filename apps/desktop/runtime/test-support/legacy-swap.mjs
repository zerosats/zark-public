import { randomBytes } from 'node:crypto';
const identifier = () => randomBytes(16).toString('hex');
const secret = () => randomBytes(32).toString('hex');

// Seed the same persisted phases as a wallet interrupted before upgrading.
export async function seedLegacySwap(controller, action, args) {
  switch (action) {
    case 'swapPublish': {
      const coin = await controller.coin(args.coin);
      const swap = { id: identifier(), role: 'maker', coin: coin.id, amountSat: coin.amountSat, phase: 'publishing', token: secret() };
      controller.state.swaps.push(swap); await controller.save(); await controller.legacySwap.publish(swap); break;
    }
    case 'swapJoin': {
      const coin = await controller.coin(args.coin);
      const offers = await controller.relay.listOffers();
      const offer = offers.find(o => o.id === args.offer && o.amountSat === coin.amountSat);
      if (!offer) throw new Error('Offer unavailable');
      await controller.checkAddress(offer.receiveAddress, 'zark');
      const swap = { id: identifier(), offerId: offer.id, offerExpiresAt: offer.expiresAt, role: 'joiner', coin: coin.id, amountSat: coin.amountSat, peerAddress: offer.receiveAddress, phase: 'claiming', token: secret() };
      controller.state.swaps.push(swap); await controller.save(); await controller.legacySwap.join(swap); break;
    }
  }
  await controller.render();
}
